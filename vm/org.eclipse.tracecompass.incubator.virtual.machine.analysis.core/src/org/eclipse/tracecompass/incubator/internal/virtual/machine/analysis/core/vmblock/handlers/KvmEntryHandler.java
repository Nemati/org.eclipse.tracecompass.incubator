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

        //Long cpuCacheMisses = ((Long)content.getField("context._perf_cpu_cache_misses").getValue()); //$NON-NLS-1$
        Long cpuCacheMisses = 0L;

        if (!tid2pid.containsKey(tid.intValue())) {
            tid2pid.put(tid.intValue(), pid.intValue());
        }

        if (pid2VM.containsKey(pid.intValue())) {
            pid2VM.get(pid.intValue()).setTid2Vcpu(tid.intValue(), vCPU_ID.intValue());

        } else {

            blockVMclass VMclass = new blockVMclass(pid.intValue(),tid.intValue(),vCPU_ID.intValue());
            pid2VM.put(pid.intValue(),VMclass);
        }
        Long cpuExCacheMisses = KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuCacheMiss(vCPU_ID.intValue());


        KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpuCacheMiss(vCPU_ID.intValue(),cpuCacheMisses);

        if (cpuExCacheMisses > 0L) {
            //System.out.println(cpuCacheMisses-cpuExCacheMisses);
            int cacheMissQuark = VMblockAnalysisUtils.getvCPUcacheMisses(ss, pid.intValue(), vCPU_ID.intValue());
            Long diffMiss = cpuCacheMisses - cpuExCacheMisses;
            VMblockAnalysisUtils.setLong(ss, cacheMissQuark, ts, diffMiss);
        }


        int vCPUStatusQuark = VMblockAnalysisUtils.getvCPUStatus(ss, pid.intValue(), vCPU_ID.intValue());
        int value ;
        String lastCr3 = pid2VM.get(pid.intValue()).getCr3(vCPU_ID.intValue());

        if (KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuReasonSet(vCPU_ID.intValue()) == 0) {
            Long endTs = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsEnd(vCPU_ID.intValue());
            value = StateValues.VCPU_STATUS_SYSCALL_WAIT;
            if (!KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID.intValue()).equals(12)) {
                value = StateValues.VCPU_PREEMPTED_BY_HOST_PROCESS;
                int quark = VMblockAnalysisUtils.getProcessCr3ThreadInternalQuark(ss, pid.intValue(), lastCr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, 0);

                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, value);
            }
            if (endTs!=null) {
                VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, endTs, value);
            }


            Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3tsEnd(lastCr3);
            Integer processQuark = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), lastCr3);

            VMblockAnalysisUtils.setProcessCr3Value(ss, processQuark, end, value);

            Long startTs = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID.intValue());
            value = StateValues.VCPU_STATUS_RUNNING_ROOT;

            if (startTs!=null) {
                VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, startTs, value);
            }
        }
        value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
        VMblockAnalysisUtils.setvCPUStatus(ss, vCPUStatusQuark, ts, value);
        String lastSP = pid2VM.get(pid.intValue()).getVcpu2InsideThread(vCPU_ID.intValue());
        int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), lastCr3);
        VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
        if (lastSP!=null) {
            quark = VMblockAnalysisUtils.getProcessCr3SPStatusQuark(ss, pid.intValue(), lastCr3,lastSP);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
        }

        // ------------------------- Nested VM part ----------------------------------------------

        String nestedVM = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedVM(vCPU_ID.intValue());
        String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedProcess(vCPU_ID.intValue());
        Integer lastExit = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID.intValue());

        // Check if a nested VM Process should be set
        if ( (lastExit.equals(24)|| lastExit.equals(20)  )) {

            if (nestedProcess.equals("0")) {
                // It is first time process for nested VM is running
                // Read the last block state
                // set nested process on vcpu
                KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedProcess(vCPU_ID.intValue(),lastCr3);
                Long blocktsProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).getBlockTimeStampProcess(lastCr3);
                if (!blocktsProcess.equals(0L)) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(lastCr3, 0L);
                    value = KvmEntryHandler.pid2VM.get(pid.intValue()).getWaitReason(vCPU_ID.intValue());
                    if (value == 0 ) {
                        value = StateValues.VCPU_STATUS_BLOCKED;
                    }
                    quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, lastCr3);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blocktsProcess, value);
                }

            }

            value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
            quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, lastCr3);
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

            quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);


        } else if (!nestedVM.equals("0") && !nestedProcess.equals("0")) {
            // Nested VM is running on vcpu
            // We have the nested process cr3
            // Check if it is being changed
            if ( !KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(lastCr3) && !nestedProcess.equals(lastCr3)) {
                // It has been changed
                // set block state for nested Process
                // add lastCr3 as new nested Process
                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(nestedProcess, ts+1);
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                value = StateValues.VCPU_STATUS_BLOCKED;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                Long blocktsProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).getBlockTimeStampProcess(lastCr3);
                if (!blocktsProcess.equals(0L)) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(lastCr3, 0L);
                    value = StateValues.VCPU_STATUS_WAIT_FOR_TASK;
                    //value = StateValues.VCPU_STATUS_WAIT_FOR_TIMER;
                    quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, lastCr3);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blocktsProcess, value);
                }
                // change the state of vcpu
                // Changes to HL2
                quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            } else if (KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(lastCr3)) {
                // We know the nested VM process and it goes to L!
                quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

            } else if (nestedProcess.equals(lastCr3)) {
                // It is nested vm
                quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), nestedVM, vCPU_ID.longValue());
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
            }
        }
        /*
        else if (nestedVM.equals("0") && nestedProcess.equals("0") && KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(lastCr3) && !lastExit.equals(0)) {
            // In some cases the Nested VM exit with 12 but still the hypervisor is running
            KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedVM(vCPU_ID.intValue(), lastCr3);

            Long blocktsvcpu = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(lastCr3).getBlockTimeStamp(vCPU_ID.intValue());
            quark = VMblockAnalysisUtils.getNestedVcpuStatus(ss, pid.intValue(), lastCr3, vCPU_ID.longValue());

            if (!blocktsvcpu.equals(0L)) {
                value = StateValues.VCPU_STATUS_RUNNING_ROOT;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, blocktsvcpu, value);
            }
            value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
            VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);


        }
*/


    }

}
