/*******************************************************************************
 * Copyright (c) 2016 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;



import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers.VMblockAnalysisUtils;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;


/**
 * @author Hani Nemati
 */
public class KvmInjIrqHandler extends VMblockAnalysisEventHandler {

    public KvmInjIrqHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {


        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long irq = checkNotNull((Long)content.getField("irq").getValue()); //$NON-NLS-1$
        if (KvmEntryHandler.tid2pid.containsKey(tid.intValue())) {
            int vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuReasonSet(vCPU_ID) == 0) {
                //System.out.println(irq);
                if (VMblockAnalysisUtils.formatTimeAbs(ts).equals("11:42:31.854864763")) {
                    System.out.println("Time: "+KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("timer"));
                    System.out.println("Task: "+KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("task"));
                    System.out.println("Disk: "+KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("disk"));
                    System.out.println("Net: "+KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("net"));
                }
                if (irq.equals(239L)) {
                    // timer
                    Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                    Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                    if (end != null && start != null) {
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);

                        Long timerWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("timer");
                        timerWait +=start-end;
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("timer", timerWait);
                        int waitQuark = VMblockAnalysisUtils.getTimerQuark(ss, pid.intValue());
                        VMblockAnalysisUtils.setWait(ss, waitQuark, ts, timerWait);

                        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                        int value = StateValues.VCPU_STATUS_WAIT_FOR_TIMER;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                        value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);


                    }
                } else if (irq.equals(251L) || irq.equals(252L)|| irq.equals(253L)) {
                    //task

                    Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                    Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);

                    if (end != null && start != null) {
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);
                        Long taskWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("task"); //$NON-NLS-1$
                        taskWait +=start-end;
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("task", taskWait); //$NON-NLS-1$
                        int waitQuark = VMblockAnalysisUtils.getTaskQuark(ss, pid.intValue());
                        VMblockAnalysisUtils.setWait(ss, waitQuark, ts, taskWait);
                        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                        int value = StateValues.VCPU_STATUS_WAIT_FOR_TASK;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                        value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);
                    }
                } else if (irq.equals(KvmEntryHandler.pid2VM.get(pid.intValue()).getDiskIrq())) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);

                    // Disk
                    Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                    Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                    if (end != null && start != null) {
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);
                        Long diskWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("disk"); //$NON-NLS-1$
                        diskWait +=start-end;
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("disk", diskWait); //$NON-NLS-1$
                        int waitQuark = VMblockAnalysisUtils.getDiskQuark(ss, pid.intValue());
                        VMblockAnalysisUtils.setWait(ss, waitQuark, ts, diskWait);
                        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                        int value = StateValues.VCPU_STATUS_WAIT_FOR_DISK;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                        value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);
                    }
                } else if (irq.equals(KvmEntryHandler.pid2VM.get(pid.intValue()).getNetIrq())){
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);

                // Network
                Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                if (end != null && start != null) {
                    Long netWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("net"); //$NON-NLS-1$
                    netWait +=start-end;
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("net", netWait); //$NON-NLS-1$
                    int waitQuark = VMblockAnalysisUtils.getNetQuark(ss, pid.intValue());
                    VMblockAnalysisUtils.setWait(ss, waitQuark, ts, netWait);
                    int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                    int value = StateValues.VCPU_STATUS_WAIT_FOR_NET;
                    VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                    value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                    VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);
                }
                }
                else {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);

                    Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                    Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                    if (end != null && start != null) {
                        Long unknownWait = KvmEntryHandler.pid2VM.get(pid.intValue()).getWait("unknown"); //$NON-NLS-1$
                        unknownWait +=start-end;
                        KvmEntryHandler.pid2VM.get(pid.intValue()).setWait("unknown", unknownWait); //$NON-NLS-1$
                        int waitQuark = VMblockAnalysisUtils.getUnknownQuark(ss, pid.intValue());
                        VMblockAnalysisUtils.setWait(ss, waitQuark, ts, unknownWait);
                        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
                        int value = StateValues.VCPU_STATUS_UNKNOWN;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, end, value);
                        value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, start, value);
                    }
                }
            } else if (tid.equals(pid)||tid.equals(1L)) {
                // block thread
                if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setDiskIrq(irq);
                }
            }

        }
    }
}
