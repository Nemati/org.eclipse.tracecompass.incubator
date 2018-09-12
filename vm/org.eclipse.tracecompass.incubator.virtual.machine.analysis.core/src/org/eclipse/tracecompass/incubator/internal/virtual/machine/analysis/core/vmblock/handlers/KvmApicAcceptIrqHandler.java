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
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.blockAnalysisAttribute;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;



/**
 * @author Hani Nemati
 */
public class KvmApicAcceptIrqHandler extends VMblockAnalysisEventHandler {

    public KvmApicAcceptIrqHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

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
        Long vec = checkNotNull((Long)content.getField("vec").getValue()); //$NON-NLS-1$
        //if ( KvmEntryHandler.pid2VM.get(vhost_pid.intValue()).net2pid.)
        if (KvmEntryHandler.net2VM.containsKey(tid.intValue())) {
            Integer vhost_pid = KvmEntryHandler.net2VM.get(tid.intValue());
            if (KvmEntryHandler.pid2VM.containsKey(vhost_pid)) {
                KvmEntryHandler.pid2VM.get(vhost_pid).setNetIrq(vec);
                Integer truePID = KvmEntryHandler.pid2VM.get(vhost_pid).getVmPid();
                int quark = ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, truePID.toString(),  "irq", "net");
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vec.intValue());

            }
        } else  if (pid.equals(tid)) {
            if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).setDiskIrq(vec);
                int quark =  ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, pid.toString(),  "irq", "disk");
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vec.intValue());

            }
        }
        boolean hani = false;
        if (hani) {
            if (KvmEntryHandler.tid2pid.containsKey(tid.intValue())) {
                int vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
                if (KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuReasonSet(vCPU_ID) == 0) {
                    if (vec.equals(239L) || vec.equals(238L)) {
                        // timer
                        Long start = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID);
                        Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID);
                        if (end != null && start != null) {
                            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuReasonSet(vCPU_ID, 1);
                            KvmEntryHandler.pid2VM.get(pid.intValue()).setWaitReason(vCPU_ID, 7);

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

                            // Process Handling
                            String cr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID);
                            System.out.println(cr3);
                            if (cr3 != null) {

                                int quark = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), cr3);
                                value = StateValues.VCPU_STATUS_WAIT_FOR_TIMER;
                                end = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3tsEnd(cr3);
                                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, end, value);
                                start = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3tsStart(cr3);
                                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, start, value);
                            }


                        }
                    }
                }
            }
        }

    }

}
