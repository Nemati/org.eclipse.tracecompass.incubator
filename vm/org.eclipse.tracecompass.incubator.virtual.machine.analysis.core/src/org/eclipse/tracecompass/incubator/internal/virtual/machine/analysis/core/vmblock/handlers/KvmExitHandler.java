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

                String nestedVM =  KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedVM(vCPU_ID);
                String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedProcess(vCPU_ID);

                if (!nestedVM.equals("0") && !nestedProcess.equals("0")) {
                    // A nested VM was running on this vcpu
                    // make vcpu nested vm and process to zero
                    // save the time stamp for them
                    //
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedProcess(vCPU_ID, "0");
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedVM(vCPU_ID, "0");
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStamp(vCPU_ID, ts+1);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(cr3,ts+1);
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                    value = StateValues.VCPU_STATUS_BLOCKED;
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                    quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

                } else if (!nestedVM.equals("0") && nestedProcess.equals("0")) {
                    // a hypervisor was running
                    // add the timestamp for that hypervisor
                }


            }





            // -------------------- Handles the Nested VM for reason = 24 ------------------------

            String nestedVM =  KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedVM(vCPU_ID);
            String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedProcess(vCPU_ID);
            if (exit_reason == 24L||exit_reason == 20L) {
                if (!KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3)) {
                    blockNestedVMclass newNestedVM = new blockNestedVMclass(cr3);
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setNestedVM(cr3, newNestedVM);
                }
                if (nestedVM.equals("0")) {
                    // It is first time the hypervisor is running
                    // for the vcpu view change the value of wait
                    // for the process view do nothing till find the exact nested process
                    KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedVM(vCPU_ID, cr3);
                    value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID);
                    if (value == 0 ) {
                        value = StateValues.VCPU_STATUS_BLOCKED;
                    }
                    Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).getBlockTimeStamp(vCPU_ID);
                    int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3, vCPU_ID.longValue());
                    if (!blockts.equals(0L)) {
                        VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                        KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3).setBlockTimeStamp(vCPU_ID, 0L);
                    }
                    value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                }
            }

         // -------------------- Handles the Nested VM for other reasons ------------------------

            if (!nestedVM.equals("0") && nestedProcess.equals("0")) {
                // It is not first time VM is running on this vcpu
                // We do not know the nested process
                int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            } else if (!nestedVM.equals("0") && !nestedProcess.equals("0")) {
                // It is not first time Nested VM is running on this vcpu
                // we know the nested process
                // we can change the status of process for nested vm
                int quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }


    }

}
