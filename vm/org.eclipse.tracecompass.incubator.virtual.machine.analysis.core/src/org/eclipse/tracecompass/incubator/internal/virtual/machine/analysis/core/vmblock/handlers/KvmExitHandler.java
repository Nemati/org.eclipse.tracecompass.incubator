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
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

/**
 * @author Hani Nemati
 */
public class KvmExitHandler extends VMblockAnalysisEventHandler {

    public KvmExitHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {
        super(layout, sp);
    }

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
        Long exit_reason = checkNotNull((Long)content.getField("exit_reason").getValue()); //$NON-NLS-1$

        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {

            Integer vCPU_ID = KvmEntryHandler.pid2VM.get(pid.intValue()).getvcpu(tid.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setLastExit(vCPU_ID, exit_reason.intValue());



            int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID);
            int value = StateValues.VCPU_STATUS_RUNNING_ROOT;


            VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);
            int lastExitQuark = VMblockAnalysisUtils.getLastExitQuark(ss, pid.intValue(), vCPU_ID);
            VMblockAnalysisUtils.setLastExit(ss, lastExitQuark, ts, exit_reason.intValue());
            @SuppressWarnings("null")
            String cr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID);
            String insideThread = KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpu2InsideThread(vCPU_ID);
            if (cr3 != null && insideThread!=null ) {
                //KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3tsStart(cr3, ts);
                int quark = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getProcessCr3SPStatusQuark(ss, pid.intValue(), cr3,insideThread);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }
            if (exit_reason == 12L) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3tsEnd(cr3, ts+1);

                String cr3Nested = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNested(vCPU_ID);

                if (!cr3Nested.equals("0")) {
                    // one means it is exited from nested VM but still should be exited from VM level
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNested(vCPU_ID, "0");
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3Nested, vCPU_ID.longValue());
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setBlockTimeStamp(vCPU_ID, ts+1);
                    value = StateValues.VCPU_STATUS_BLOCKED;
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                }
                // added for non-nested
                if (KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3)) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNested(vCPU_ID, "0");
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).setBlockTimeStamp(vCPU_ID, ts+1);
                    value = StateValues.VCPU_STATUS_BLOCKED;
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                }
            }

            String cr3Nested = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNested(vCPU_ID);

            // For nested VM

            if (KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3) && exit_reason != 12L && ((exit_reason != 24L && exit_reason != 20L))) {

                Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).getBlockTimeStamp(vCPU_ID);
                if (!blockts.equals(0L)) {
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());

                    value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID);
                    if (value == 0 ) {
                        value = StateValues.VCPU_STATUS_BLOCKED;
                    }
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).setBlockTimeStamp(vCPU_ID, 0L);
                }

                int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }

            if(!cr3Nested.equals("0") ) {
                Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getBlockTimeStamp(vCPU_ID);
                if (!blockts.equals(0L)) {
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3Nested, vCPU_ID.longValue());
                    value = StateValues.VCPU_STATUS_BLOCKED;
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setBlockTimeStamp(vCPU_ID, 0L);
                }
            }

            if (exit_reason == 24L||exit_reason == 20L) {
                if (!KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3)) {
                    blockNestedVMclass newNestedVM = new blockNestedVMclass(cr3);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setNestedVM(cr3, newNestedVM);
                }
                KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNested(vCPU_ID, cr3);

                Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).getBlockTimeStamp(vCPU_ID);
                if (!blockts.equals(0L)) {
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());

                    value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID);
                    if (value == 0 ) {
                        value = StateValues.VCPU_STATUS_BLOCKED;
                    }
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).setBlockTimeStamp(vCPU_ID, 0L);
                }

                int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            } else if(!cr3Nested.equals("0")) {
                int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3Nested, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }



        }


    }

}
