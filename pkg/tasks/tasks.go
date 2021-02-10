/*
 * Copyright 2020 Mandelsoft. All rights reserved.
 *  This file is licensed under the Apache Software License, v. 2 except as noted
 *  otherwise in the LICENSE file
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package tasks

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

var tasksKey = ctxutil.SimpleKey("tasks")

const CMD_TASK_PREFIX = "task:"

type Tasks interface {
	ScheduleTask(task Task, override bool)
}

func GetTaskClient(controller controller.Interface) Tasks {
	return controller.GetEnvironment().GetOrCreateSharedValue(tasksKey, func() interface{} {
		return newTasks(controller)
	}).(Tasks)
}

type tasks struct {
	controller.Interface
	logger logger.LogContext
	lock   sync.Mutex
	tasks  map[string]Task
	active map[string]Task
}

func newTasks(c controller.Interface) Tasks {
	return &tasks{
		Interface: c,
		logger:    logger.Get(c.GetEnvironment().GetContext()).NewContext("area", "tasks"),
		tasks:     map[string]Task{},
		active:    map[string]Task{},
	}
}

func (this *tasks) activate(id string) Task {
	this.lock.Lock()
	defer this.lock.Unlock()
	task := this.tasks[id]
	if task != nil {
		delete(this.tasks, id)
		this.active[id] = task
	}
	return task
}

func (this *tasks) done(task Task, keep bool) {
	id := task.Id()
	this.lock.Lock()
	defer this.lock.Unlock()
	old := this.active[id]
	if old != nil {
		delete(this.active, id)
		if keep && (task != old || this.tasks[id] == nil) {
			this.tasks[id] = task
		}
	}
}

func (this *tasks) ScheduleTask(task Task, override bool) {
	id := task.Id()

	this.lock.Lock()
	defer this.lock.Unlock()

	if old := this.tasks[id]; old == nil || override {
		this.tasks[id] = task
	}
	this.logger.Infof("SCHEDULE TASK %s", id)
	this.EnqueueCommand(CMD_TASK_PREFIX + task.Id())
}

func (this *tasks) execute(logger logger.LogContext, id string) reconcile.Status {
	this.logger.Infof("EXECUTE TASK %s", id)
	task := this.activate(id)
	result := task.Execute(logger)
	if (!result.IsSucceeded() && !result.IsFailed() && result.Interval != 0) || result.Interval > 0 {
		this.done(task, true)
		this.logger.Infof("TASK %s will be rescheduled RESULT: %v", id, result)
	} else {
		this.done(task, false)
		result.Interval = 0
		this.logger.Infof("TASK %s DONE RESULT: %v", id, result)
	}
	return result
}

////////////////////////////////////////////////////////////////////////////////

type Task interface {
	Id() string
	Execute(logger logger.LogContext) reconcile.Status
}

type BaseTask struct {
	ttype string
	name  string
}

func NewBaseTask(ttype, name string) BaseTask {
	return BaseTask{ttype: ttype, name: name}
}

func (this *BaseTask) Id() string {
	return fmt.Sprintf("%s:%s", this.ttype, this.name)
}

func (this *BaseTask) Execute(logger logger.LogContext) reconcile.Status {
	return reconcile.Succeeded(logger)
}

////////////////////////////////////////////////////////////////////////////////

func TaskReconciler(count int) controller.ConfigurationModifier {
	return func(configuration controller.Configuration) controller.Configuration {
		return configuration.WorkerPool("tasks", count, 0).
			Reconciler(createTaskReconciler, "tasks").
			ForCommandMatchers(utils.NewStringGlobMatcher(CMD_TASK_PREFIX + "*"))
	}
}

func createTaskReconciler(controller controller.Interface) (reconcile.Interface, error) {
	return &taskReconciler{controller: controller, tasks: GetTaskClient(controller).(*tasks)}, nil
}

type taskReconciler struct {
	reconcile.DefaultReconciler
	controller controller.Interface
	tasks      *tasks
}

func (this *taskReconciler) Command(logger logger.LogContext, cmd string) reconcile.Status {
	i := strings.Index(cmd, ":")
	if i <= 0 {
		return reconcile.Succeeded(logger)
	}
	id := cmd[i+1:]
	return this.tasks.execute(logger, id)
}
