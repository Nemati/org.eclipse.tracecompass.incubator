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

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

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
public class KvmVcpuEnterGuestHandler extends VMblockAnalysisEventHandler {

    public KvmVcpuEnterGuestHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {

        super(layout, sp);

    }

    @SuppressWarnings("null")
    @Override
    public void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event) {

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }

        ITmfEventField content = event.getContent();
        Long vCPU_ID = checkNotNull((Long)content.getField("vcpuID").getValue()); //$NON-NLS-1$
        String cr3 = checkNotNull(content.getField("cr3tmp").getValue().toString()); //$NON-NLS-1$
        String sp = Long.toUnsignedString(content.getFieldValue(Long.class, "sptmp"));
        BigInteger bigSP = new BigInteger(sp,10);
        String Hex = bigSP.toString(16);
        Integer startSP = 1;
        Integer endSP = 12;
        String insideThread = "";
        if (Hex.length()>13) {
            insideThread = Hex.substring(startSP, endSP);

        }
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$

        final long ts = event.getTimestamp().getValue();
        if (!KvmEntryHandler.tid2pid.containsKey(tid.intValue())) {
            KvmEntryHandler.tid2pid.put(tid.intValue(), pid.intValue());
        }




        if (KvmEntryHandler.pid2VM.containsKey(pid.intValue())) {

            Integer lastExit = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastExit(vCPU_ID.intValue());

            if (Hex.length()<=13) {
                BigInteger lastThread = KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpu2Thread(vCPU_ID.intValue());
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2Thread(vCPU_ID.intValue(), bigSP);
                if (!lastThread.equals(bigSP) && lastExit.equals(1)) {
                    //Long cacheMiss = KvmEntryHandler.pid2VM.get(pid.intValue()).getVcpuCacheDiff(vCPU_ID.intValue());
                    //System.out.println(cacheMiss +":"+lastThread+":"+bigSP);
                }
            }



            String runningNestedVM = KvmEntryHandler.pid2VM.get(pid.intValue()).runningNested(vCPU_ID.intValue());
            // cr3 to fake TID
            if (KvmEntryHandler.pid2VM.get(pid.intValue()).getcr3toftid(cr3) == 0 && !KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3) && runningNestedVM.equals("0") && !cr3.equals("0") ) {

                int lastFakeTid = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastFtid();
                KvmEntryHandler.pid2VM.get(pid.intValue()).setcr3toftid(cr3,lastFakeTid+1);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setLastFtid(lastFakeTid+1);
                int processQuark = ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, String.valueOf(pid.intValue()), blockAnalysisAttribute.PROCESS, cr3.toString());
                ss.updateOngoingState(lastFakeTid+1, processQuark);
            } else if (!runningNestedVM.equals("0") && !KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3) && KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(runningNestedVM).getcr3toftid(cr3)==0) {

                int lastFakeTid = KvmEntryHandler.pid2VM.get(pid.intValue()).getLastFtid();
                KvmEntryHandler.pid2VM.get(pid.intValue()).setLastFtid(lastFakeTid+1);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setcr3toftid(cr3,lastFakeTid+1);
                KvmEntryHandler.pid2VM.get(pid.intValue()).setLastFtid(lastFakeTid+1);
                int processQuark = ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, String.valueOf(pid.intValue()), blockAnalysisAttribute.PROCESS, cr3.toString());
                ss.updateOngoingState( lastFakeTid+1, processQuark);

                //lastFakeTid = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(runningNestedVM).getLastFtid();
                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(runningNestedVM).setcr3toftid(cr3,lastFakeTid+1);
                //KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(runningNestedVM).setLastFtid(lastFakeTid+1);
                processQuark = ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, String.valueOf(pid.intValue()), blockAnalysisAttribute.NESTED, runningNestedVM, blockAnalysisAttribute.PROCESS ,cr3);
                ss.updateOngoingState( lastFakeTid+1, processQuark);

                String nestedVM = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedVM(vCPU_ID.intValue());
                int nestedVMftid = KvmEntryHandler.pid2VM.get(pid.intValue()).getcr3toftid(nestedVM);
                int nestedVMQuark = ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, String.valueOf(pid.intValue()), blockAnalysisAttribute.NESTED, nestedVM.toString());
                ss.updateOngoingState( nestedVMftid, nestedVMQuark);


            }
            // thread Block state
            String lastInsideThread = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3toSP(cr3);
            if (lastInsideThread!=null && !lastInsideThread.equals(insideThread) && !lastInsideThread.equals("0")) {
                int quark = VMblockAnalysisUtils.getProcessCr3SPStatusQuark(ss, pid.intValue(), cr3,lastInsideThread);
                int value1 = StateValues.VCPU_STATUS_BLOCKED;
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value1);
            }

            KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3toSP(cr3, insideThread);
            KvmEntryHandler.pid2VM.get(pid.intValue()).setTid2Vcpu(tid.intValue(), vCPU_ID.intValue());
            String lastCr3 = KvmEntryHandler.pid2VM.get(pid.intValue()).getCr3(vCPU_ID.intValue());
            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2cr3(vCPU_ID.intValue(), cr3);
            KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2InsideThread(vCPU_ID.intValue(), insideThread);

            // Handling nested VM process change
            String nestedVM = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedVM(vCPU_ID.intValue());
            String nestedProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getRunningNestedProcess(vCPU_ID.intValue());
            if (!nestedVM.equals("0")&& !nestedProcess.equals("0") && !nestedProcess.equals(cr3) && !KvmEntryHandler.pid2VM.get(pid.intValue()).isNested(cr3)) {
                // It means new nested process with #cr3 for that nested VM is on the vCPU
                // Change the nestedProcess.

                KvmEntryHandler.pid2VM.get(pid.intValue()).setRunningNestedProcess(vCPU_ID.intValue(), cr3);


                // Change the sched out time for nestedProcess

                KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(nestedProcess, ts+1);
                int value = StateValues.VCPU_STATUS_BLOCKED;
                int quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, nestedProcess);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);


                // set wait for task process for new nested cr3

                Long blocktsProcess = KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).getBlockTimeStampProcess(cr3);
                if (!blocktsProcess.equals(0L)) {
                    KvmEntryHandler.pid2VM.get(pid.intValue()).getNestedVM(nestedVM).setBlockTimeStampProcess(cr3, 0L);
                    value = StateValues.VCPU_STATUS_WAIT_FOR_TASK;
                    quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, cr3);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, blocktsProcess, value);
                }

                // set HL2 for new nested process #cr3

                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT_L2;
                quark = VMblockAnalysisUtils.getNestedProcessStatus(ss, pid.intValue(), nestedVM, cr3);
                VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);

            }


            //////////////////////////////////

            //int quark1 = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
            //int value1 = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
            //VMblockAnalysisUtils.setvCPUStatus(ss, quark1, ts, value1);
            int quark1 = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
            VMblockAnalysisUtils.setCr3Value(ss, quark1, ts, cr3);
            quark1 = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
            VMblockAnalysisUtils.setCr3Value(ss, quark1, ts, sp);

            quark1 = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
            VMblockAnalysisUtils.setProcessCr3Value(ss, quark1, ts, vCPU_ID.intValue());

            ///////////////////////////////////



            if (lastCr3 == null) {
                // it is the first time
                //int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                //int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                //VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                int quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());
            }
            else if (lastCr3.equals("0")) { //$NON-NLS-1$
                // It is the first after scheduling
                //int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                //int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;

                //VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                Long timeStartSP = KvmEntryHandler.pid2VM.get(pid.intValue()).getTsStart(vCPU_ID.intValue());

                KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3tsStart(cr3, timeStartSP);

                int quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());
            }
            else if (lastCr3.equals(cr3)){
                // No change -- set the sp
                KvmEntryHandler.pid2VM.get(pid.intValue()).setVcpu2sp(vCPU_ID.intValue(), sp);
                //int quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                //int value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                //VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                int quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, cr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());




            }
            else  if (!lastCr3.equals(cr3)) {

                // Finding cache misses

                if (lastExit.equals(1)) {

                    String FILENAME = "cacheMisses.csv";
                    BufferedWriter bw = null;
                    FileWriter fw = null;
                    String content1 = "This is the content to write into file\n";
                    try {
                        fw = new FileWriter(FILENAME);
                        bw = new BufferedWriter(fw);
                        bw.write(content1);
                    } catch (IOException e) {

                        e.printStackTrace();

                    } finally {
                        try {

                            if (bw != null) {
                                bw.close();
                            }

                            if (fw != null) {
                                fw.close();
                            }

                        } catch (IOException ex) {

                            ex.printStackTrace();

                        }
                    }


                }
                ////////////////////////

                int value1 = StateValues.WAIT;
                quark1 = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), lastCr3);

                VMblockAnalysisUtils.setvCPUStatus(ss, quark1, ts, value1);

                KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3tsEnd(lastCr3, ts+1);

                KvmEntryHandler.pid2VM.get(pid.intValue()).setCR3tsStart(cr3, ts);
                int quark = VMblockAnalysisUtils.getProcessCr3StatusQuark(ss, pid.intValue(), cr3);
                int value = StateValues.VCPU_STATUS_WAIT_FOR_TASK;
                Long end = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3tsEnd(cr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, end, value);
                quark = VMblockAnalysisUtils.getProcessCr3WakeUpQuark(ss, pid.intValue(), cr3);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, lastCr3);
                // start = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3tsStart(cr3);



                value = StateValues.VCPU_STATUS_BLOCKED;
                quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), lastCr3);
                lastInsideThread = KvmEntryHandler.pid2VM.get(pid.intValue()).getCR3toSP(lastCr3);
                if (lastInsideThread!=null && !lastInsideThread.equals("0")) {
                    quark = VMblockAnalysisUtils.getProcessCr3SPStatusQuark(ss, pid.intValue(), lastCr3,lastInsideThread);
                    VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                }

                //quark = VMblockAnalysisUtils.getCr3Status(ss, pid.intValue(), cr3);
                value = StateValues.VCPU_STATUS_RUNNING_NON_ROOT;
                //VMblockAnalysisUtils.setvCPUStatus(ss, quark, ts, value);
                quark = VMblockAnalysisUtils.getVcpuCr3Value(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, lastCr3);
                quark = VMblockAnalysisUtils.getVcpuSpValue(ss, pid.intValue(), vCPU_ID);
                VMblockAnalysisUtils.setCr3Value(ss, quark, ts, sp);
                quark = VMblockAnalysisUtils.getProcessCr3VcpuQuark(ss, pid.intValue(),lastCr3);
                VMblockAnalysisUtils.setProcessCr3Value(ss, quark, ts, vCPU_ID.intValue());




            }
        } else {
            blockVMclass VMclass = new blockVMclass(pid.intValue(),tid.intValue(),vCPU_ID.intValue(), cr3);
            KvmEntryHandler.pid2VM.put(pid.intValue(),VMclass);
        }

    }

}
