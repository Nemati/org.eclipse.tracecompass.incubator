/**
 * @author Vahid Azhari & Hani Nemati
 *
 * For a given VM Experiment creates two files recording average and
 * frequency of waits and run periods as follows:
 *
 * avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT
 * frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT
 *
 * The files are located in the directory of the shell spawning eclipse (probably!)
 * This is the vectorization phase after which a python script should be run
 * for doing clustering/classification/etc.
 *
 * TODO add analysis parameters for begin and end of time frame
 * TODO test with various trace files
 * TODO produce output viewable in trace compass, e.g., a horizontal histogram
 */
package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.vectorizer;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;
//import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.module.StateValues;
//import org.eclipse.tracecompass.incubator.callstack.core.tests.stubs.CallStackAnalysisStub;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.VMblockAnalysis;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateSystemDisposedException;
import org.eclipse.tracecompass.statesystem.core.exceptions.TimeRangeException;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
//import org.eclipse.tracecompass.common.core.NonNullUtils;
//import org.eclipse.tracecompass.incubator.callstack.core.instrumented.IFlameChartProvider;
//import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.virtual.resources.Messages;
//import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers.VMblockAnalysisStateProvider;
import org.eclipse.tracecompass.tmf.core.analysis.IAnalysisModule;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisModule;
import org.eclipse.tracecompass.tmf.core.analysis.requirements.TmfAbstractAnalysisRequirement;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
//import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;

import java.io.UnsupportedEncodingException;
//import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
/**
 * @author Vahid Azhari & Hani Nemati
 *
 */
public class VMblockVectorizerAnalysis extends TmfAbstractAnalysisModule {



    /** The ID of this analysis module */
    public static final String ID = "org.eclipse.tracecompass.incubator.virtual.machine.analysis.VMblockVectorizerAnalysis"; //$NON-NLS-1$
    public static final String VM_BLOCK_ID = "org.eclipse.tracecompass.incubator.virtual.machine.analysis.VMblockAnalysis"; //$NON-NLS-1$

    private static final Set<TmfAbstractAnalysisRequirement> REQUIREMENTS;

    private VMblockAnalysis aVMblock = null;
    private @Nullable ITmfStateSystem fStateSystem = null;



    static {
        REQUIREMENTS = checkNotNull(Collections.EMPTY_SET);
    }

    // @SuppressWarnings({ "resource", "null" })
    @Override
    protected boolean executeAnalysis(@NonNull IProgressMonitor monitor) throws TmfAnalysisException {
        // TODO Auto-generated method stub
        ITmfTrace trace = getTrace();
        aVMblock = TmfTraceUtils.getAnalysisModuleOfClass(trace, VMblockAnalysis.class, VM_BLOCK_ID);//get a reference to the dependent analysis
        checkNotNull(aVMblock);
        boolean flag = false;
        Iterable<IAnalysisModule> dependentAnalyses = getDependentAnalyses();//Genevieve: make sure all dependent analysis are finished first
        for (IAnalysisModule module : dependentAnalyses) {
            if (!(module instanceof VMblockAnalysis)) {
                return false;
            }
            flag = module.waitForCompletion(); //Genevieve: is this how I'm supposed to do this? ... by waiting for them
        }
        if (flag == true) {
            fStateSystem = aVMblock.getStateSystem(); //record resulting state system after these analysis are finished
            checkNotNull(fStateSystem);
        }

        String suppDir = TmfTraceManager.getSupplementaryFileDir(trace);
        String traceDir = trace.getName()+"_exp";
        //System.out.println(suppDir);
        long start = fStateSystem.getStartTime();
        long end = fStateSystem.getCurrentEndTime();

        // You could add a periodic sampling of data, for now, I just set it to the whole trace

        writeProcessFeatures(fStateSystem,suppDir,end-start);
        writeVcpuFeatures(fStateSystem,suppDir,end-start);
        writeVCPUInternalStatus(fStateSystem,suppDir,end-start);
        writeVcpuExitFreq(fStateSystem,suppDir,end-start);
        diskFeatures(fStateSystem,suppDir,end-start);
        netFeatures(fStateSystem,suppDir,end-start);

        String TRACE_FOLDER_LIST = "folder_list.txt"; //$NON-NLS-1$
        String listFileName = suppDir + File.separator + ".." + File.separator + TRACE_FOLDER_LIST; //one level above
        try {
            Files.write(Paths.get(listFileName), (traceDir + System.lineSeparator()).getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (UnsupportedEncodingException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        } catch (IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        return true;
    }
    // write
    private static void writeVcpuExitFreq(ITmfStateSystem stateSystem,String suppDir, Long period) {

        // Reading block
        List<Integer> quarks = stateSystem.getQuarks("VMs","*","vCPU","*","LastExit");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime = start;
        while (endTime < end ) {

            endTime +=period;

            //System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
            Iterable<ITmfStateInterval> iterable = null;
            try {
                iterable = stateSystem.query2D(quarks, startTime, endTime);
                startTime = endTime;
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }
            Map<Integer, Map<Long,Long>> quarkToExitFreq = new HashMap<>();

            Long freq;
            for (ITmfStateInterval interval : iterable) {//iterate over all intervals and collect metrics
                Integer quark = interval.getAttribute();
                Long number = interval.getStateValue().unboxLong();
                if (quarkToExitFreq.containsKey(quark)) {
                    Map<Long,Long> exitReason = quarkToExitFreq.get(quark);
                    if (exitReason.containsKey(number)) {
                        freq = exitReason.get(number)+1;
                        exitReason.put(number, freq);
                        quarkToExitFreq.put(quark, exitReason);
                    } else {
                        exitReason.put(number, 1L);
                    }
                } else {
                    Map<Long,Long> exitReason = new HashMap<>();
                    exitReason.put(number, 1L);
                    quarkToExitFreq.put(quark, exitReason);
                }
            }

            File fileFreq = null;

            String freqFileName = "cpuExit["+startTime.toString()+"].vector";

            try {
                fileFreq = new File(suppDir+freqFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }


            FileOutputStream streamFreq = null;

            try {
                streamFreq = new FileOutputStream(fileFreq);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;

            for (Integer quark : quarks) {//iterate over quarks
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1]+"/"+path[3];
                //compute average durations

                Map<Long,Long> exitReasons = quarkToExitFreq.get(quark);
                String freqInBytes;
                for (Long number : exitReasons.keySet()){
                    if (number>0) {
                        freqInBytes = key +"/"+number.toString() +"," +exitReasons.get(number).toString()+"\n";
                        byte[] writeBytes = freqInBytes.getBytes();
                        try {
                            streamFreq.write(writeBytes);
                        } catch (IOException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                    }
                }


            }
            try {
                streamFreq.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }



        } // end of while


    }

    // File: VMPID, writeBlock, readBlock, writeLatency, readLatency
    private static void diskFeatures(ITmfStateSystem stateSystem, String suppDir, Long period) {
        // Reading block
        List<Integer> quarksReadBlock = stateSystem.getQuarks("VMs","*","Disk","read","block");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarksReadBlock);
        List<Integer> quarksReadLatency = stateSystem.getQuarks("VMs","*","Disk","read","latency");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarksReadLatency);
        List<Integer> quarksWriteBlock = stateSystem.getQuarks("VMs","*","Disk","write","block");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarksWriteBlock);
        List<Integer> quarksWriteLatency = stateSystem.getQuarks("VMs","*","Disk","write","latency");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarksWriteLatency);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime = start;
        Map<String,Long> readBlock = new HashMap<>();
        Map<String,Long> readLatency = new HashMap<>();
        Map<String,Long> writeBlock = new HashMap<>();
        Map<String,Long>writeLatency = new HashMap<>();

        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterableReadBlock = null;
            Iterable<ITmfStateInterval> iterableReadLatency = null;
            Iterable<ITmfStateInterval> iterableWriteBlock = null;
            Iterable<ITmfStateInterval> iterableWriteLatency = null;

            try {
                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterableReadBlock = stateSystem.query2D(quarksReadBlock, times);
                iterableReadLatency = stateSystem.query2D(quarksReadBlock, times);
                iterableWriteBlock = stateSystem.query2D(quarksWriteBlock, times);
                iterableWriteLatency = stateSystem.query2D(quarksWriteLatency, times);
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;
            HashMap<String,Integer> keySet = new HashMap<>();

            for (ITmfStateInterval interval : iterableReadBlock) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1];
                keySet.put(key, 1);
                readBlock.put(key, interval.getStateValue().unboxLong()) ;
            }
            for (ITmfStateInterval interval : iterableReadLatency) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1];
                keySet.put(key, 1);

                readLatency.put(key, interval.getStateValue().unboxLong()) ;
            }
            for (ITmfStateInterval interval : iterableWriteBlock) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1];
                keySet.put(key, 1);

                writeBlock.put(key, interval.getStateValue().unboxLong())  ;
            }
            for (ITmfStateInterval interval : iterableWriteLatency) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1];
                keySet.put(key, 1);

                writeLatency.put(key, interval.getStateValue().unboxLong()) ;
            }
            // Writing to file
            File fileDisk = null;

            String diskFileName = "disk["+startTime.toString()+"].vector";
            startTime = endTime;
            try {
                fileDisk = new File(suppDir+diskFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }


            FileOutputStream streamDisk = null;

            try {
                streamDisk = new FileOutputStream(fileDisk);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }


            String key1;

            for (Map.Entry<String, Integer> entry : keySet.entrySet()) {
                Long diskWriteBlock=0L, diskReadBlock=0L, diskWriteLatency=0L, diskReadLatency=0L;
                key1 = entry.getKey();
                if (writeBlock.containsKey(key1)) {
                    diskWriteBlock = writeBlock.get(key1);
                }
                if (readBlock.containsKey(key1)) {
                    diskReadBlock = readBlock.get(key1);
                }
                if (writeLatency.containsKey(key1)) {
                    diskWriteLatency = writeLatency.get(key1);
                }
                if (readLatency.containsKey(key1)) {
                    diskReadLatency = readLatency.get(key1);
                }
                byte[] freqInBytes = (key1+","+Long.toString(diskWriteBlock)+","+Long.toString(diskReadBlock)+","+Long.toString(diskWriteLatency)+","+Long.toString(diskReadLatency)+"\n").getBytes();
                try {
                    streamDisk.write(freqInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            // closing the file
            try {
                streamDisk.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamDisk.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }

    }

    private static void netFeatures(ITmfStateSystem stateSystem, String suppDir ,Long period) {
        // Reading block
        List<Integer> quarksRec = stateSystem.getQuarks("VMs","*","Net","rec");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$
        checkNotNull(quarksRec);

        List<Integer> quarksTra = stateSystem.getQuarks("VMs","*","Net","tra");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$
        checkNotNull(quarksTra);

        Map<String,Long> netTra = new HashMap<>();
        Map<String,Long> netRec = new HashMap<>();
        HashMap<String,Integer> keySet = new HashMap<>();

        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime = start;
        while (endTime < end ) {
            endTime +=period;


            Iterable<ITmfStateInterval> iterableNetRec = null;
            Iterable<ITmfStateInterval> iterableNetTra = null;
            try {
                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterableNetRec = stateSystem.query2D(quarksRec, times);
                iterableNetTra = stateSystem.query2D(quarksTra, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;

            for (ITmfStateInterval interval : iterableNetRec) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);
                key = path[1];
                keySet.put(key, 1);
                netRec.put(key, interval.getStateValue().unboxLong());
            }
            for (ITmfStateInterval interval : iterableNetTra) {
                Integer quark = interval.getAttribute();
                path = stateSystem.getFullAttributePathArray(quark);

                key = path[1];
                keySet.put(key, 1);
                netTra.put(key, interval.getStateValue().unboxLong());
            }

            File fileNet = null;

            String netFileName = "net["+startTime.toString()+"].vector";
            startTime = endTime;
            try {
                fileNet = new File(suppDir+netFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }


            FileOutputStream streamNet = null;

            try {
                streamNet = new FileOutputStream(fileNet);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String key1;


            for (Map.Entry<String, Integer> entry : keySet.entrySet()) {
                Long netRecSum=0L, netTraSum=0L;
                key1 = entry.getKey();
                if (netRec.containsKey(key1)) {
                    netRecSum = netRec.get(key1);
                }
                if (netTra.containsKey(key1)) {
                    netTraSum = netTra.get(key1);
                }
                byte[] freqInBytes = (key1+","+Long.toString(netRecSum)+","+
                        Long.toString(netTraSum)+"\n").getBytes();
                try {
                    streamNet.write(freqInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            // close the file
            try {
                streamNet.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamNet.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }
    }

    // The output file contains Preemption for: Preemption VMVM, HOSTVM, VMProc, VMThread, Inj_Timer, Inj_Task, Inj_Disk, Inj_Net
    // VMVM : A VM preempts another VM
    // HostVM: Host Process preempts VM
    // VMProc: VM processes preempt each other
    // VMThread: VM process threads preempt each other.
    // Inj_timer: when a timer is injected to vcpu
    // Inj_task: when a timer is injected to vcpu
    // Inj_disk: when a timer is injected to vcpu
    // Inj_net: when a timer is injected to vcpu
    private void writeVCPUInternalStatus(ITmfStateSystem stateSystem, String suppDir, Long period) {

        // Preemption VMVM, HOSTVM, VMProc, VMThread

        Map<Integer, Long> quarkToVMProcessPreemptionFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMThreadPreemptionFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMVMPreemptionFreq = new HashMap<>();
        Map<Integer, Long> quarkToHostVMPreemptionFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMTimerFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMTaskFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMNetFreq = new HashMap<>();
        Map<Integer, Long> quarkToVMDiskFreq = new HashMap<>();
        List<Integer> quarks = stateSystem.getQuarks("VMs","*","vCPU","*","internal");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime = start;
        while (endTime < end ) {

            endTime +=period;

            //System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
            Iterable<ITmfStateInterval> iterable = null;
            try {
                iterable = fStateSystem.query2D(quarks, startTime, endTime);
                startTime = endTime;
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }
            long freq;
            for (ITmfStateInterval interval : iterable) {//iterate over all intervals and collect metrics
                Integer quark = interval.getAttribute();
                switch(interval.getStateValue().unboxInt()) {//update various process states: duration and frequency

                case StateValues.VCPU_PREEMPTED_BY_VM:
                    if (quarkToVMVMPreemptionFreq.containsKey(quark)) {
                        freq = quarkToVMVMPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMVMPreemptionFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_PREEMPTED_BY_HOST_PROCESS:
                    if (quarkToHostVMPreemptionFreq.containsKey(quark)) {
                        freq = quarkToHostVMPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToHostVMPreemptionFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_PREEMPTED_INTERNALLY_BY_PROCESS:
                    if (quarkToVMProcessPreemptionFreq.containsKey(quark)) {
                        freq = quarkToVMProcessPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMProcessPreemptionFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_PREEMPTED_INTERNALLY_BY_THREAD:
                    if (quarkToVMThreadPreemptionFreq.containsKey(quark)) {
                        freq = quarkToVMThreadPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMThreadPreemptionFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_INJ_TIMER:
                    if (quarkToVMTimerFreq.containsKey(quark)) {
                        freq = quarkToVMTimerFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMTimerFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_INJ_TASK:
                    if (quarkToVMTaskFreq.containsKey(quark)) {
                        freq = quarkToVMTaskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMTaskFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_INJ_DISK:
                    if (quarkToVMDiskFreq.containsKey(quark)) {
                        freq = quarkToVMDiskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMDiskFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_INJ_NET:
                    if (quarkToVMNetFreq.containsKey(quark)) {
                        freq = quarkToVMNetFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    freq++;
                    quarkToVMNetFreq.put(quark,freq);
                    break;
                default:
                    //TODO throw some exception and provide error message here
                    break;
                }
            }

            File fileFreq = null;

            String freqFileName = "cpuInternal["+startTime.toString()+"].vector";

            try {
                fileFreq = new File(suppDir+freqFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }


            FileOutputStream streamFreq = null;

            try {
                streamFreq = new FileOutputStream(fileFreq);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;
            Long freqVMVM=0L;
            Long freqHostVM=0L;
            Long freqVMProc=0L;
            Long freqVMThread=0L;
            Long freqVMTimer=0L;
            Long freqVMTask=0L;
            Long freqVMDisk=0L;
            Long freqVMNet=0L;
            for (Integer quark : quarks) {//iterate over quarks
                path = fStateSystem.getFullAttributePathArray(quark);
                key = path[1]+"/"+path[3];
                //compute average durations


                if (quarkToVMVMPreemptionFreq.containsKey(quark)) {
                    freqVMVM = quarkToVMVMPreemptionFreq.get(quark);
                    quarkToVMVMPreemptionFreq.remove(quark);
                }
                if (quarkToHostVMPreemptionFreq.containsKey(quark)) {
                    freqHostVM = quarkToHostVMPreemptionFreq.get(quark);
                    quarkToHostVMPreemptionFreq.remove(quark);
                }
                if (quarkToVMProcessPreemptionFreq.containsKey(quark)) {
                    freqVMProc = quarkToVMProcessPreemptionFreq.get(quark);
                    quarkToVMProcessPreemptionFreq.remove(quark);
                }
                if (quarkToVMThreadPreemptionFreq.containsKey(quark)) {
                    freqVMThread = quarkToVMThreadPreemptionFreq.get(quark);
                    quarkToVMThreadPreemptionFreq.remove(quark);
                }
                if (quarkToVMTimerFreq.containsKey(quark)) {
                    freqVMTimer = quarkToVMTimerFreq.get(quark);
                    quarkToVMTimerFreq.remove(quark);
                }
                if (quarkToVMTaskFreq.containsKey(quark)) {
                    freqVMTask = quarkToVMTaskFreq.get(quark);
                    quarkToVMTaskFreq.remove(quark);
                }
                if (quarkToVMDiskFreq.containsKey(quark)) {
                    freqVMDisk = quarkToVMDiskFreq.get(quark);
                    quarkToVMDiskFreq.remove(quark);
                }
                if (quarkToVMNetFreq.containsKey(quark)) {
                    freqVMNet = quarkToVMNetFreq.get(quark);
                    quarkToVMNetFreq.remove(quark);
                }
                //store in file
                // Preemption VMVM, HOSTVM, VMProc, VMThread, Inj_Timer, Inj_Task, Inj_Disk, Inj_Net
                byte[] freqInBytes = (key+","+Long.toString(freqVMVM)+","+
                        Long.toString(freqHostVM)+","+
                        Long.toString(freqVMProc)+","+
                        Long.toString(freqVMThread)+","+
                        Long.toString(freqVMTimer)+","+
                        Long.toString(freqVMTask)+","+
                        Long.toString(freqVMDisk)+","+
                        Long.toString(freqVMNet)+"\n").getBytes();

                try {
                    streamFreq.write(freqInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }


            }
            try {
                streamFreq.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } // end while


    }

    private void writeVcpuFeatures(ITmfStateSystem stateSystem, String suppDir, Long period) {

        Map<Integer, Long> quarkToTimerDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TIMER = 7
        Map<Integer, Long> quarkToTimerFreq = new HashMap<>();
        Map<Integer, Long> quarkToTaskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TASK = 6
        Map<Integer, Long> quarkToTaskFreq = new HashMap<>();
        Map<Integer, Long> quarkToDiskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_DISK = 8
        Map<Integer, Long> quarkToDiskFreq = new HashMap<>();
        Map<Integer, Long> quarkToNetDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_NET = 9
        Map<Integer, Long> quarkToNetFreq = new HashMap<>();
        Map<Integer, Long> quarkToUnknownDuration = new HashMap<>(); //VCPU_STATUS_UNKNOWN = 0
        Map<Integer, Long> quarkToUnknownFreq = new HashMap<>();
        Map<Integer, Long> quarkToRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_ROOT = 1
        Map<Integer, Long> quarkToRootFreq = new HashMap<>();
        Map<Integer, Long> quarkToNonRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_NON_ROOT = 2
        Map<Integer, Long> quarkToNonRootFreq = new HashMap<>();
        Map<Integer, Long> quarkToPreemptionDuration = new HashMap<>();
        Map<Integer, Long> quarkToPreemptionFreq = new HashMap<>();


        List<Integer> quarks = stateSystem.getQuarks("VMs","*","vCPU","*","Status");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime = start;

        while (endTime < end ) {

            endTime +=period;

            //System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
            Iterable<ITmfStateInterval> iterable = null;
            try {
                iterable = fStateSystem.query2D(quarks, startTime, endTime);
                startTime = endTime;
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }

            long dur;
            long freq;
            for (ITmfStateInterval interval : iterable) {//iterate over all intervals and collect metrics
                Integer quark = interval.getAttribute();
                Long intEnd = interval.getEndTime() > endTime? endTime:interval.getEndTime();
                Long intStart = interval.getStartTime() > startTime ? interval.getStartTime():startTime;

                dur = intEnd-intStart;
                dur = interval.getEndTime()- interval.getStartTime();
                switch(interval.getStateValue().unboxInt()) {//update various process states: duration and frequency

                case StateValues.VCPU_STATUS_UNKNOWN:
                    if (quarkToUnknownDuration.containsKey(quark)) {
                        dur += quarkToUnknownDuration.get(quark);
                        freq = quarkToUnknownFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToUnknownDuration.put(quark,dur);
                    freq++;
                    quarkToUnknownFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_RUNNING_ROOT:
                    if (quarkToRootDuration.containsKey(quark)) {
                        dur += quarkToRootDuration.get(quark);
                        freq = quarkToRootFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToRootDuration.put(quark,dur);
                    freq++;
                    quarkToRootFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_RUNNING_NON_ROOT:
                    if (quarkToNonRootDuration.containsKey(quark)) {
                        dur += quarkToNonRootDuration.get(quark);
                        freq = quarkToNonRootFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToNonRootDuration.put(quark,dur);
                    freq++;
                    quarkToNonRootFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_DISK:
                    if (quarkToDiskDuration.containsKey(quark)) {
                        dur += quarkToDiskDuration.get(quark);
                        freq = quarkToDiskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToDiskDuration.put(quark,dur);
                    freq++;
                    quarkToDiskFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_NET:
                    if (quarkToNetDuration.containsKey(quark)) {
                        dur += quarkToNetDuration.get(quark);
                        freq = quarkToNetFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToNetDuration.put(quark,dur);
                    freq++;
                    quarkToNetFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_TIMER:
                    if (quarkToTimerDuration.containsKey(quark)) {
                        dur += quarkToTimerDuration.get(quark);
                        freq = quarkToTimerFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToTimerDuration.put(quark,dur);
                    freq++;
                    quarkToTimerFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_TASK:
                    if (quarkToTaskDuration.containsKey(quark)) {
                        dur += quarkToTaskDuration.get(quark);
                        freq = quarkToTaskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToTaskDuration.put(quark,dur);
                    freq++;
                    quarkToTaskFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_STATUS_PREEMPTED_L0:
                    if (quarkToPreemptionDuration.containsKey(quark)) {
                        dur += quarkToPreemptionDuration.get(quark);
                        freq = quarkToPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToPreemptionDuration.put(quark,dur);
                    freq++;
                    quarkToPreemptionFreq.put(quark,freq);
                    break;
                default:
                    //TODO throw some exception and provide error message here
                    break;
                }
            }
            //iterate over quarks and write vectors to files as follows:
            //avgdur.vector:    VMID/CPUID,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT, Preemption_L0
            //frequency.vector: VMID/CPUID,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT, Preemption_L0

            //open output file for storing feature vectors

            File fileAvg = null;
            File fileFreq = null;
            String avgFileName = "cpuAvgdur["+startTime.toString()+"].vector";
            String freqFileName = "cpuFrequency["+startTime.toString()+"].vector";
            try {
                fileAvg = new File(suppDir+avgFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
            try {
                fileFreq = new File(suppDir+freqFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }

            FileOutputStream streamAvg = null;
            FileOutputStream streamFreq = null;
            try {
                streamAvg = new FileOutputStream(fileAvg);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq = new FileOutputStream(fileFreq);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;
            Long avgUnknown;
            Long avgRoot;
            Long avgNonRoot;
            Long avgDisk;
            Long avgNet;
            Long avgTimer;
            Long avgTask;
            Long freqUnknown;
            Long freqRoot;
            Long freqNonRoot;
            Long freqDisk;
            Long freqNet;
            Long freqTimer;
            Long freqTask;
            Long avgPreemption;
            Long freqPreemption;
            for (Integer quark : quarks) {//iterate over quarks
                path = fStateSystem.getFullAttributePathArray(quark);
                key = path[1]+"/"+path[3];
                //compute average durations
                avgUnknown = 0L;
                freqUnknown = 0L;
                if (quarkToUnknownFreq.containsKey(quark)) {
                    avgUnknown = quarkToUnknownDuration.get(quark) / quarkToUnknownFreq.get(quark);
                    freqUnknown = quarkToUnknownFreq.get(quark);
                    quarkToUnknownDuration.remove(quark);
                    quarkToUnknownFreq.remove(quark);
                }
                avgRoot = 0L;
                freqRoot = 0L;
                if (quarkToRootFreq.containsKey(quark)) {
                    avgRoot = quarkToRootDuration.get(quark) / quarkToRootFreq.get(quark);
                    freqRoot = quarkToRootFreq.get(quark);
                    quarkToRootDuration.remove(quark);
                    quarkToRootFreq.remove(quark);
                }
                avgNonRoot = 0L;
                freqNonRoot = 0L;
                if (quarkToNonRootFreq.containsKey(quark)) {
                    avgNonRoot = quarkToNonRootDuration.get(quark) / quarkToNonRootFreq.get(quark);
                    freqNonRoot = quarkToNonRootFreq.get(quark);
                    quarkToNonRootDuration.remove(quark);
                    quarkToNonRootFreq.remove(quark);
                }
                avgDisk = 0L;
                freqDisk = 0L;
                if (quarkToDiskFreq.containsKey(quark)) {
                    avgDisk = quarkToDiskDuration.get(quark) / quarkToDiskFreq.get(quark);
                    freqDisk = quarkToDiskFreq.get(quark);
                    quarkToDiskDuration.remove(quark);
                    quarkToDiskFreq.remove(quark);
                }
                avgNet = 0L;
                freqNet = 0L;
                if (quarkToNetFreq.containsKey(quark)) {
                    avgNet = quarkToNetDuration.get(quark) / quarkToNetFreq.get(quark);
                    freqNet = quarkToNetFreq.get(quark);
                    quarkToNetDuration.remove(quark);
                    quarkToNetFreq.remove(quark);
                }
                avgTimer = 0L;
                freqTimer = 0L;
                if (quarkToTimerFreq.containsKey(quark)) {
                    avgTimer = quarkToTimerDuration.get(quark) / quarkToTimerFreq.get(quark);
                    freqTimer = quarkToTimerFreq.get(quark);
                    quarkToTimerDuration.remove(quark);
                    quarkToTimerFreq.remove(quark);
                }
                avgTask = 0L;
                freqTask = 0L;
                if (quarkToTaskFreq.containsKey(quark)) {
                    avgTask = quarkToTaskDuration.get(quark) / quarkToTaskFreq.get(quark);
                    freqTask = quarkToTaskFreq.get(quark);
                    quarkToTaskDuration.remove(quark);
                    quarkToTaskFreq.remove(quark);
                }

                avgPreemption = 0L;
                freqPreemption = 0L;
                if (quarkToPreemptionFreq.containsKey(quark)) {
                    avgPreemption = quarkToPreemptionDuration.get(quark) / quarkToPreemptionFreq.get(quark);
                    freqPreemption = quarkToPreemptionFreq.get(quark);
                    quarkToPreemptionDuration.remove(quark);
                    quarkToPreemptionFreq.remove(quark);
                }

                //store in file
                byte[] avgInBytes = (key+","+Long.toString(avgTimer)+","+
                        Long.toString(avgDisk)+","+
                        Long.toString(avgNet)+","+
                        Long.toString(avgTask)+","+
                        Long.toString(avgUnknown)+","+
                        Long.toString(avgNonRoot)+","+
                        Long.toString(avgRoot)+","+
                        Long.toString(avgPreemption)+"\n").getBytes();
                byte[] freqInBytes = (key+","+Long.toString(freqTimer)+","+
                        Long.toString(freqDisk)+","+
                        Long.toString(freqNet)+","+
                        Long.toString(freqTask)+","+
                        Long.toString(freqUnknown)+","+
                        Long.toString(freqNonRoot)+","+
                        Long.toString(freqRoot)+","+
                        Long.toString(freqPreemption)+"\n").getBytes();
                try {
                    streamAvg.write(avgInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                try {
                    streamFreq.write(freqInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }


            }

            try {
                streamAvg.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamAvg.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } // end while





    }


    private void writeProcessFeatures(ITmfStateSystem stateSystem, String suppDir, Long period) {

        Map<Integer, Long> quarkToTimerDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TIMER = 7
        Map<Integer, Long> quarkToTimerFreq = new HashMap<>();
        Map<Integer, Long> quarkToTaskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TASK = 6
        Map<Integer, Long> quarkToTaskFreq = new HashMap<>();
        Map<Integer, Long> quarkToDiskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_DISK = 8
        Map<Integer, Long> quarkToDiskFreq = new HashMap<>();
        Map<Integer, Long> quarkToNetDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_NET = 9
        Map<Integer, Long> quarkToNetFreq = new HashMap<>();
        Map<Integer, Long> quarkToUnknownDuration = new HashMap<>(); //VCPU_STATUS_UNKNOWN = 0
        Map<Integer, Long> quarkToUnknownFreq = new HashMap<>();
        Map<Integer, Long> quarkToRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_ROOT = 1
        Map<Integer, Long> quarkToRootFreq = new HashMap<>();
        Map<Integer, Long> quarkToNonRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_NON_ROOT = 2
        Map<Integer, Long> quarkToNonRootFreq = new HashMap<>();
        Map<Integer, Long> quarkToPreemptionDuration = new HashMap<>(); // VCPU_STATUS_PREEMPTION_L0 = 3
        Map<Integer, Long> quarkToPreemptionFreq = new HashMap<>();
        //get all needed wait times for all processes
        List<Integer> quarks = stateSystem.getQuarks("VMs","*","Process","*","Status");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;
        Long startTime=start;


        while (endTime < end ) {


            endTime +=period;

            //System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
            Iterable<ITmfStateInterval> iterable = null;
            try {
                iterable = fStateSystem.query2D(quarks, startTime, endTime);
                startTime = endTime;
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
                // TODO Auto-generated catch block
                e2.printStackTrace();
            }

            long dur;
            long freq;
            for (ITmfStateInterval interval : iterable) {//iterate over all intervals and collect metrics
                Integer quark = interval.getAttribute();
                Long intEnd = interval.getEndTime() > endTime? endTime:interval.getEndTime();
                Long intStart = interval.getStartTime() > startTime ? interval.getStartTime():startTime;

                dur = intEnd-intStart;
                dur = interval.getEndTime()- interval.getStartTime();
                switch(interval.getStateValue().unboxInt()) {//update various process states: duration and frequency

                case StateValues.VCPU_STATUS_UNKNOWN:
                    if (quarkToUnknownDuration.containsKey(quark)) {
                        dur += quarkToUnknownDuration.get(quark);
                        freq = quarkToUnknownFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToUnknownDuration.put(quark,dur);
                    freq++;
                    quarkToUnknownFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_RUNNING_ROOT:
                    if (quarkToRootDuration.containsKey(quark)) {
                        dur += quarkToRootDuration.get(quark);
                        freq = quarkToRootFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToRootDuration.put(quark,dur);
                    freq++;
                    quarkToRootFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_RUNNING_NON_ROOT:
                    if (quarkToNonRootDuration.containsKey(quark)) {
                        dur += quarkToNonRootDuration.get(quark);
                        freq = quarkToNonRootFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToNonRootDuration.put(quark,dur);
                    freq++;
                    quarkToNonRootFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_DISK:
                    if (quarkToDiskDuration.containsKey(quark)) {
                        dur += quarkToDiskDuration.get(quark);
                        freq = quarkToDiskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToDiskDuration.put(quark,dur);
                    freq++;
                    quarkToDiskFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_NET:
                    if (quarkToNetDuration.containsKey(quark)) {
                        dur += quarkToNetDuration.get(quark);
                        freq = quarkToNetFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToNetDuration.put(quark,dur);
                    freq++;
                    quarkToNetFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_TIMER:
                    if (quarkToTimerDuration.containsKey(quark)) {
                        dur += quarkToTimerDuration.get(quark);
                        freq = quarkToTimerFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToTimerDuration.put(quark,dur);
                    freq++;
                    quarkToTimerFreq.put(quark,freq);
                    break;

                case StateValues.VCPU_STATUS_WAIT_FOR_TASK:
                    if (quarkToTaskDuration.containsKey(quark)) {
                        dur += quarkToTaskDuration.get(quark);
                        freq = quarkToTaskFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToTaskDuration.put(quark,dur);
                    freq++;
                    quarkToTaskFreq.put(quark,freq);
                    break;
                case StateValues.VCPU_STATUS_PREEMPTED_L0:
                    if (quarkToPreemptionDuration.containsKey(quark)) {
                        dur += quarkToPreemptionDuration.get(quark);
                        freq = quarkToPreemptionFreq.get(quark);
                    }
                    else {
                        freq = 0;
                    }
                    quarkToPreemptionDuration.put(quark,dur);
                    freq++;
                    quarkToPreemptionFreq.put(quark,freq);
                    break;
                default:
                    //TODO throw some exception and provide error message here
                    break;
                }
            }


            //iterate over quarks and write vectors to files as follows:
            //avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT, Preemption_L0
            //frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT, Preemption_L0

            //open output file for storing feature vectors
            File fileAvg = null;
            File fileFreq = null;
            String avgFileName = "processAvgdur["+startTime.toString()+"].vector";
            String freqFileName = "processFrequency["+startTime.toString()+"].vector";
            try {
                fileAvg = new File(suppDir+avgFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
            try {
                fileFreq = new File(suppDir+freqFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }

            FileOutputStream streamAvg = null;
            FileOutputStream streamFreq = null;
            try {
                streamAvg = new FileOutputStream(fileAvg);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq = new FileOutputStream(fileFreq);
            } catch (FileNotFoundException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            String[] path;
            String key;
            Long avgUnknown;
            Long avgRoot;
            Long avgNonRoot;
            Long avgDisk;
            Long avgNet;
            Long avgTimer;
            Long avgTask;
            Long avgPreemption;
            Long freqUnknown;
            Long freqRoot;
            Long freqNonRoot;
            Long freqDisk;
            Long freqNet;
            Long freqTimer;
            Long freqTask;
            Long freqPreemption;

            for (Integer quark : quarks) {//iterate over quarks
                path = fStateSystem.getFullAttributePathArray(quark);
                key = path[1]+"/"+path[3];
                //compute average durations
                avgUnknown = 0L;
                freqUnknown = 0L;
                if (quarkToUnknownFreq.containsKey(quark)) {
                    avgUnknown = quarkToUnknownDuration.get(quark) / quarkToUnknownFreq.get(quark);
                    freqUnknown = quarkToUnknownFreq.get(quark);
                    quarkToUnknownDuration.remove(quark);
                    quarkToUnknownFreq.remove(quark);
                }
                avgRoot = 0L;
                freqRoot = 0L;
                if (quarkToRootFreq.containsKey(quark)) {
                    avgRoot = quarkToRootDuration.get(quark) / quarkToRootFreq.get(quark);
                    freqRoot = quarkToRootFreq.get(quark);
                    quarkToRootDuration.remove(quark);
                    quarkToRootFreq.remove(quark);
                }
                avgNonRoot = 0L;
                freqNonRoot = 0L;
                if (quarkToNonRootFreq.containsKey(quark)) {
                    avgNonRoot = quarkToNonRootDuration.get(quark) / quarkToNonRootFreq.get(quark);
                    freqNonRoot = quarkToNonRootFreq.get(quark);
                    quarkToNonRootDuration.remove(quark);
                    quarkToNonRootFreq.remove(quark);
                }
                avgDisk = 0L;
                freqDisk = 0L;
                if (quarkToDiskFreq.containsKey(quark)) {
                    avgDisk = quarkToDiskDuration.get(quark) / quarkToDiskFreq.get(quark);
                    freqDisk = quarkToDiskFreq.get(quark);
                    quarkToDiskDuration.remove(quark);
                    quarkToDiskFreq.remove(quark);
                }
                avgNet = 0L;
                freqNet = 0L;
                if (quarkToNetFreq.containsKey(quark)) {
                    avgNet = quarkToNetDuration.get(quark) / quarkToNetFreq.get(quark);
                    freqNet = quarkToNetFreq.get(quark);
                    quarkToNetDuration.remove(quark);
                    quarkToNetFreq.remove(quark);
                }
                avgTimer = 0L;
                freqTimer = 0L;
                if (quarkToTimerFreq.containsKey(quark)) {
                    avgTimer = quarkToTimerDuration.get(quark) / quarkToTimerFreq.get(quark);
                    freqTimer = quarkToTimerFreq.get(quark);
                    quarkToTimerDuration.remove(quark);
                    quarkToTimerFreq.remove(quark);
                }
                avgTask = 0L;
                freqTask = 0L;
                if (quarkToTaskFreq.containsKey(quark)) {
                    avgTask = quarkToTaskDuration.get(quark) / quarkToTaskFreq.get(quark);
                    freqTask = quarkToTaskFreq.get(quark);
                    quarkToTaskDuration.remove(quark);
                    quarkToTaskFreq.remove(quark);
                }
                avgPreemption = 0L;
                freqPreemption = 0L;
                if (quarkToPreemptionFreq.containsKey(quark)) {
                    avgPreemption = quarkToPreemptionDuration.get(quark) / quarkToPreemptionFreq.get(quark);
                    freqPreemption = quarkToPreemptionFreq.get(quark);
                    quarkToPreemptionDuration.remove(quark);
                    quarkToPreemptionFreq.remove(quark);
                }
                //store in file
                byte[] avgInBytes = (key+","+Long.toString(avgTimer)+","+
                        Long.toString(avgDisk)+","+
                        Long.toString(avgNet)+","+
                        Long.toString(avgTask)+","+
                        Long.toString(avgUnknown)+","+
                        Long.toString(avgNonRoot)+","+
                        Long.toString(avgRoot)+","+
                        Long.toString(avgPreemption)+"\n").getBytes();
                byte[] freqInBytes = (key+","+Long.toString(freqTimer)+","+
                        Long.toString(freqDisk)+","+
                        Long.toString(freqNet)+","+
                        Long.toString(freqTask)+","+
                        Long.toString(freqUnknown)+","+
                        Long.toString(freqNonRoot)+","+
                        Long.toString(freqRoot)+","+
                        Long.toString(freqPreemption)+"\n").getBytes();
                try {
                    streamAvg.write(avgInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                try {
                    streamFreq.write(freqInBytes);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }


            }

            try {
                streamAvg.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamAvg.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                streamFreq.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } // end while

    }



    @Override
    protected void canceling() {
        // TODO Auto-generated method stub

    }
    @SuppressWarnings("null")
    @Override
    public Iterable<TmfAbstractAnalysisRequirement> getAnalysisRequirements() {
        return REQUIREMENTS;
    }

    @Override
    protected Iterable<IAnalysisModule> getDependentAnalyses() {
        ITmfTrace trace = getTrace();
        aVMblock = TmfTraceUtils.getAnalysisModuleOfClass(trace, VMblockAnalysis.class, VM_BLOCK_ID);
        checkNotNull(aVMblock);
        return Collections.singleton(aVMblock);
    }

}
