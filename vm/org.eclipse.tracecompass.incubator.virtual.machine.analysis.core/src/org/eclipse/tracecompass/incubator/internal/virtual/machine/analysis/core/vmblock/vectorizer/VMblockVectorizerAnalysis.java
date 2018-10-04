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
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.virtual.resources.StateValues;
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
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

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
        writeProcessFeatures(fStateSystem,100000000000L);
        writeVcpuFeatures(fStateSystem,100000000000L);
        diskFeatures(fStateSystem,1000000000L);
        netFeatures(fStateSystem,1000000000L);
        return true;
    }

    private static void diskFeatures(ITmfStateSystem stateSystem, Long period) {
        // Reading block
        List<Integer> quarks = stateSystem.getQuarks("VMs","*","Disk","read","block");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;

        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {
                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long block = interval.getStateValue().unboxLong();
                System.out.println("Block Read:"+block);
            }
        }
        // Reading latency for VM
        quarks = stateSystem.getQuarks("VMs","*","Disk","read","latency");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        endTime = start;



        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {
                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);
            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long latency = interval.getStateValue().unboxLong();
                System.out.println("Latency Read:"+latency);
            }
        }

        // Writing latency for VM
        quarks = stateSystem.getQuarks("VMs","*","Disk","write","latency");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        endTime = start;



        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {

                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long latency = interval.getStateValue().unboxLong();
                System.out.println("Latency write:"+latency);
            }
        }

     // Writing latency for VM
        quarks = stateSystem.getQuarks("VMs","*","Disk","write","latency");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        endTime = start;



        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {

                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long latency = interval.getStateValue().unboxLong();
                System.out.println("Latency write:"+latency);
            }
        }
    }


    private static void netFeatures(ITmfStateSystem stateSystem, Long period) {

        // Reading block
        List<Integer> quarks = stateSystem.getQuarks("VMs","*","Net","rec");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = stateSystem.getStartTime();
        long end = stateSystem.getCurrentEndTime();
        //Long period = 100000000000L;
        Long endTime = start;

        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {

                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long latency = interval.getStateValue().unboxLong();
                System.out.println("Net Rec:"+latency);
            }

        }

        // Writing latency for VM
        quarks = stateSystem.getQuarks("VMs","*","Net","tra");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        endTime = start;



        while (endTime < end ) {
            endTime +=period;
            Iterable<ITmfStateInterval> iterable = null;
            try {

                Collection<Long> times = new HashSet<>();
                times.add(endTime-1);
                iterable = stateSystem.query2D(quarks, times);

            } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            for (ITmfStateInterval interval : iterable) {
                Long latency = interval.getStateValue().unboxLong();
                System.out.println("Net Transmit:"+latency);
            }
        }

    }



    private void writeVcpuFeatures(ITmfStateSystem stateSystem, Long period) {

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

            System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
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
            //avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT
            //frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT

            //open output file for storing feature vectors
            File fileAvg = null;
            File fileFreq = null;
            String avgFileName = "cpuAvgdur["+startTime.toString()+"].vector";
            String freqFileName = "cpuFrequency["+startTime.toString()+"].vector";
            try {
                fileAvg = new File(avgFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
            try {
                fileFreq = new File(freqFileName); //$NON-NLS-1$
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


     private void writeProcessFeatures(ITmfStateSystem stateSystem, Long period) {

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

            System.out.println("subTotal["+String.valueOf(startTime)+","+String.valueOf(endTime)+"]");
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

                default:
                    //TODO throw some exception and provide error message here
                    break;
                }
            }


            //iterate over quarks and write vectors to files as follows:
            //avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT
            //frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT

            //open output file for storing feature vectors
            File fileAvg = null;
            File fileFreq = null;
            String avgFileName = "processAvgdur["+startTime.toString()+"].vector";
            String freqFileName = "processFrequency["+startTime.toString()+"].vector";
            try {
                fileAvg = new File(avgFileName); //$NON-NLS-1$
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
            try {
                fileFreq = new File(freqFileName); //$NON-NLS-1$
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

                //store in file
                byte[] avgInBytes = (key+","+Long.toString(avgTimer)+","+
                        Long.toString(avgDisk)+","+
                        Long.toString(avgNet)+","+
                        Long.toString(avgTask)+","+
                        Long.toString(avgUnknown)+","+
                        Long.toString(avgNonRoot)+","+
                        Long.toString(avgRoot)+"\n").getBytes();
                byte[] freqInBytes = (key+","+Long.toString(freqTimer)+","+
                        Long.toString(freqDisk)+","+
                        Long.toString(freqNet)+","+
                        Long.toString(freqTask)+","+
                        Long.toString(freqUnknown)+","+
                        Long.toString(freqNonRoot)+","+
                        Long.toString(freqRoot)+"\n").getBytes();
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
