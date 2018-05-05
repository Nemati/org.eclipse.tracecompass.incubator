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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
public class KvmEntryHandler extends VMblockAnalysisEventHandler {
    public static Map<Integer,blockVMclass> pid2VM = new HashMap<>();
    public static Map<Integer,Integer> net2VM = new HashMap<>();
    public static Map<Integer,Integer> tid2pid = new HashMap<>();
    public static int firstTimeStart = 1 ;
    public static Map<String,String> sysNumber2Name = new HashMap<>();
    public KvmEntryHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }
    public void readSyscall() {
        File signatureFile = new File("syscall.tbl"); //$NON-NLS-1$
        BufferedReader signatureReader ;

        try {
            signatureReader = new BufferedReader(new FileReader(signatureFile));
            String text = null;

            while ((text = signatureReader.readLine()) != null) {

                String[] syscallName = text.split("\\s+");
                sysNumber2Name.put(syscallName[0], syscallName[2]);
            }
            signatureReader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        firstTimeStart++;
    }
    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {
        if (firstTimeStart == 1) {
            readSyscall();
        }
        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        final long ts = event.getTimestamp().getValue();
        ITmfEventField content = event.getContent();
        Long vCPU_ID = checkNotNull((Long)content.getField("vcpu_id").getValue()); //$NON-NLS-1$
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$

        if (!tid2pid.containsKey(tid.intValue())) {
            tid2pid.put(tid.intValue(), pid.intValue());
        }

        if (pid2VM.containsKey(pid.intValue())) {
            pid2VM.get(pid.intValue()).setTid2Vcpu(tid.intValue(), vCPU_ID.intValue());

        } else {

            blockVMclass VMclass = new blockVMclass(pid.intValue(),tid.intValue(),vCPU_ID.intValue());
            pid2VM.put(pid.intValue(),VMclass);
        }
        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID.intValue());
        int value ;
        if (KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuReasonSet(vCPU_ID.intValue()) == 0) {
            Long endTs = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID.intValue());
            value = StateValues.VCPU_STATUS_SYSCALL_WAIT;
            if (endTs!=null) {
                VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, endTs, value);
            }
            Long startTs = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID.intValue());
            value = StateValues.VCPU_STATUS_RUNNING_ROOT;

            if (startTs!=null) {
                VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, startTs, value);
            }
        }
        value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);
        String lastCr3 = pid2VM.get(pid.intValue()).getCr3(vCPU_ID.intValue());
        String lastSP = pid2VM.get(pid.intValue()).getVcpu2InsideThread(vCPU_ID.intValue());
        int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), lastCr3);
        VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
        if (lastSP!=null) {
            quark = VMblockAnalysisUtils.getProcessCr3SPStatusQuark(ss, pid.intValue(), lastCr3,lastSP);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
        }

        // Nested VM part

        String cr3Nested = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNested(vCPU_ID.intValue());
        Integer lastExit = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID.intValue());
        if (!lastExit.equals(0) && (lastExit.equals(24)|| lastExit.equals(20))) {
            Long blocktsProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getBlockTimeStampProcess(lastCr3);
            if (!blocktsProcess.equals(0L)) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setBlockTimeStampProcess(lastCr3, 0L);
                value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID.intValue());
                if (value == 0 ) {
                    value = StateValues.VCPU_STATUS_BLOCKED;
                }                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), cr3Nested, lastCr3);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, blocktsProcess, value);
            }
            value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
            quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), cr3Nested, lastCr3);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setRunningNestedProcess(vCPU_ID.intValue(), lastCr3);
        }

        if (!cr3Nested.equals("0")) {

            Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getBlockTimeStamp(vCPU_ID.intValue());
            if (!blockts.equals(0L)) {
                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setBlockTimeStamp(vCPU_ID.intValue(), 0L);
                quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3Nested, vCPU_ID);
                value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID.intValue());
                if (value == 0 ) {
                    value = StateValues.VCPU_STATUS_BLOCKED;
                }
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                // Process inside VM

                String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getRunningNestedProcess(vCPU_ID.intValue());
                if (!nestedProcess.equals("0")) {
                    blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getBlockTimeStampProcess(nestedProcess);
                    if (!blockts.equals(0L)) {
                        KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).setBlockTimeStampProcess(nestedProcess, 0L);
                        quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), cr3Nested, nestedProcess);
                        VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                    }
                }
            }
            String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getRunningNestedProcess(vCPU_ID.intValue());
            Long blockNestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(cr3Nested).getBlockTimeStampProcess(nestedProcess);
            if (!blockNestedProcess.equals(0L)) {
                value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID.intValue());
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), cr3Nested, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockNestedProcess, value);
            }
            quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), cr3Nested, vCPU_ID.longValue());
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(lastCr3)) {
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
            } else {
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
            }

            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

            // Process inside VM



            if (!nestedProcess.equals("0")) {

                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), cr3Nested, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }


        } else if (KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(lastCr3)) {

            Long blockts = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(lastCr3).getBlockTimeStamp(vCPU_ID.intValue());
            if (!blockts.equals(0L)) {
                quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), lastCr3, vCPU_ID.longValue());

                value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID.intValue());
                if (value == 0 ) {
                    value = StateValues.VCPU_STATUS_BLOCKED;
                }
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                String runningNestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(lastCr3).getRunningNestedProcess(vCPU_ID.intValue());
                if (!runningNestedProcess.equals("0")) {
                    quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), lastCr3, runningNestedProcess);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blockts, value);
                }

                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(lastCr3).setBlockTimeStamp(vCPU_ID.intValue(), 0L);
            }

            value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
            quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), lastCr3, vCPU_ID.longValue());
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

            String runningNestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(lastCr3).getRunningNestedProcess(vCPU_ID.intValue());
            if (!runningNestedProcess.equals("0")) {
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), lastCr3, runningNestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }

        }


    }

}
