/*******************************************************************************
 * Copyright (c) 2016 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module;

import org.eclipse.tracecompass.statesystem.core.statevalue.ITmfStateValue;
import org.eclipse.tracecompass.statesystem.core.statevalue.TmfStateValue;

/**
 * State values that are used in the kernel event handler. It's much better to
 * use integer values whenever possible, since those take much less space in the
 * history file.
 *
 * @author Alexandre Montplaisir, Hani Nemati
 */
@SuppressWarnings("javadoc")
public interface StateValues {

    /* Machine Status*/
    int MACHINE_HOST = (1 << 0);
    int MACHINE_GUEST = (1 << 1);
    int MACHINE_CONTAINER = (1 << 2);
    int MACHINE_UNKNOWN = (1 << 3);

    ITmfStateValue MACHINE_HOST_VALUE = TmfStateValue.newValueInt(MACHINE_HOST);
    ITmfStateValue MACHINE_GUEST_VALUE = TmfStateValue.newValueInt(MACHINE_GUEST);
    ITmfStateValue MACHINE_HOST_AND_GUEST_VALUE = TmfStateValue.newValueInt(MACHINE_HOST + MACHINE_GUEST);
    ITmfStateValue MACHINE_CONTAINER_VALUE = TmfStateValue.newValueInt(MACHINE_CONTAINER);
    ITmfStateValue MACHINE_UNKNOWN_VALUE = TmfStateValue.newValueInt(MACHINE_UNKNOWN);

    /* CPU Status */
    int CPU_STATUS_IDLE = 0;
    /**
     * Soft IRQ raised, could happen in the CPU attribute but should not since
     * this means that the CPU went idle when a softirq was raised.
     */
    int CPU_STATUS_SOFT_IRQ_RAISED = (1 << 0);
    int CPU_STATUS_RUN_USERMODE = (1 << 1);
    int CPU_STATUS_RUN_SYSCALL = (1 << 2);
    int CPU_STATUS_SOFTIRQ = (1 << 3);
    int CPU_STATUS_IRQ = (1 << 4);
    int CPU_STATUS_IN_VM = (1 << 5);

    ITmfStateValue CPU_STATUS_IDLE_VALUE = TmfStateValue.newValueInt(CPU_STATUS_IDLE);
    ITmfStateValue CPU_STATUS_RUN_USERMODE_VALUE = TmfStateValue.newValueInt(CPU_STATUS_RUN_USERMODE);
    ITmfStateValue CPU_STATUS_RUN_SYSCALL_VALUE = TmfStateValue.newValueInt(CPU_STATUS_RUN_SYSCALL);
    ITmfStateValue CPU_STATUS_IRQ_VALUE = TmfStateValue.newValueInt(CPU_STATUS_IRQ);
    ITmfStateValue CPU_STATUS_SOFTIRQ_VALUE = TmfStateValue.newValueInt(CPU_STATUS_SOFTIRQ);
    ITmfStateValue CPU_STATUS_IN_VM_VALUE = TmfStateValue.newValueInt(CPU_STATUS_IN_VM);

    /* CPU condition*/
    int CONDITION_IN_VM = 0;
    int CONDITION_OUT_VM = 1;
    int CONDITION_UNKNOWN = 3;

    ITmfStateValue CONDITION_IN_VM_VALUE = TmfStateValue.newValueInt(CONDITION_IN_VM);
    ITmfStateValue CONDITION_OUT_VM_VALUE = TmfStateValue.newValueInt(CONDITION_OUT_VM);
    ITmfStateValue CONDITION_UNKNOWN_VALUE = TmfStateValue.newValueInt(CONDITION_UNKNOWN);

    /* Process status */
    int PROCESS_STATUS_UNKNOWN = 0;
    int PROCESS_STATUS_WAIT_BLOCKED = 1;
    int PROCESS_STATUS_RUN_USERMODE = 2;
    int PROCESS_STATUS_RUN_SYSCALL = 3;
    int PROCESS_STATUS_INTERRUPTED = 4;
    int PROCESS_STATUS_WAIT_FOR_CPU = 5;
    int PROCESS_STATUS_WAIT_UNKNOWN = 6;

    ITmfStateValue PROCESS_STATUS_UNKNOWN_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_UNKNOWN);
    /**
     * @since 1.0
     */
    ITmfStateValue PROCESS_STATUS_WAIT_UNKNOWN_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_WAIT_UNKNOWN);
    ITmfStateValue PROCESS_STATUS_WAIT_BLOCKED_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_WAIT_BLOCKED);
    ITmfStateValue PROCESS_STATUS_RUN_USERMODE_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_RUN_USERMODE);
    ITmfStateValue PROCESS_STATUS_RUN_SYSCALL_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_RUN_SYSCALL);
    ITmfStateValue PROCESS_STATUS_INTERRUPTED_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_INTERRUPTED);
    ITmfStateValue PROCESS_STATUS_WAIT_FOR_CPU_VALUE = TmfStateValue.newValueInt(PROCESS_STATUS_WAIT_FOR_CPU);

    /** Soft IRQ is raised, CPU is in user mode */
    ITmfStateValue SOFT_IRQ_RAISED_VALUE = TmfStateValue.newValueInt(CPU_STATUS_SOFT_IRQ_RAISED);

    /** If the softirq is running and another is raised at the same time. */
    ITmfStateValue SOFT_IRQ_RAISED_RUNNING_VALUE = TmfStateValue.newValueInt(CPU_STATUS_SOFT_IRQ_RAISED | CPU_STATUS_SOFTIRQ);

    int VCPU_STATUS_UNKNOWN = 0;
    int VCPU_STATUS_RUNNING_ROOT = 1;
    int VCPU_STATUS_RUNNING_NON_ROOT = 2;
    int VCPU_STATUS_PREEMPTED_L0 = 3;
    int VCPU_STATUS_PREEMPTED_L1 = 4;
    int VCPU_STATUS_PREEMPTED_L2 = 5;
    int VCPU_STATUS_WAIT_FOR_TASK = 6;
    int VCPU_STATUS_WAIT_FOR_TIMER = 7;
    int VCPU_STATUS_WAIT_FOR_DISK = 8;
    int VCPU_STATUS_WAIT_FOR_NET = 9;
    int VCPU_STATUS_BLOCKED = 10;
    int WAIT = 11;
    int SYSCALL = 12;
    int USERSPACE = 13;
    int VCPU_STATUS_SYSCALL_WAIT = 14;
    int VCPU_STATUS_RUNNING_NON_ROOT_L2 = 15;
    int VCPU_PREEMPTED_BY_HOST_PROCESS = 16;
    int VCPU_PREEMPTED_BY_VM = 17;
    int VCPU_PREEMPTED_INTERNALLY_BY_PROCESS = 18;
    int VCPU_PREEMPTED_INTERNALLY_BY_THREAD = 19;
    int VCPU_INJ_TIMER = 20;
    int VCPU_INJ_TASK = 21;
    int VCPU_INJ_NET = 22;
    int VCPU_INJ_DISK = 23;

    int VCPU_INJ_TIMER_238 = 238;
    int VCPU_INJ_TIMER_239 = 239;

    int VCPU_INJ_TASK_251 = 251;
    int VCPU_INJ_TASK_252 = 252;
    int VCPU_INJ_TASK_253 = 253;

}
