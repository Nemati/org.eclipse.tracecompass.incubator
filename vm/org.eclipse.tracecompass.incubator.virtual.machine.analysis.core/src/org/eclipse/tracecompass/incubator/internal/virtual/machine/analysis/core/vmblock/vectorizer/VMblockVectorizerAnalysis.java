/**
 * @author azhari
 *
 * For a given VM Experiment creates two files recording average and
 * frequency of waits and run periods as follows:
 *
 * avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT,IDLE
 * frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT,IDLE
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

//import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
//import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
//import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashMap;
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
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;


/**
 * @author azhari
 *
 */
public class VMblockVectorizerAnalysis extends TmfAbstractAnalysisModule {
    /** The ID of this analysis module */
    public static final String ID = "org.eclipse.tracecompass.incubator.virtual.machine.analysis.VMblockVectorizerAnalysis"; //$NON-NLS-1$
    public static final String VM_BLOCK_ID = "org.eclipse.tracecompass.incubator.virtual.machine.analysis.VMblockAnalysis"; //$NON-NLS-1$
    /*
     * File placed one level above supplementary files folder containing list of trace folders which have been analysed
     * by various runs of this analysis. This is used by external LAMI analysis to process all resulting vectors in one run.
     */
    public static final String TRACE_FOLDER_LIST = "folder_list.txt"; //$NON-NLS-1$

    private static final Set<TmfAbstractAnalysisRequirement> REQUIREMENTS;

    private VMblockAnalysis aVMblock = null;
    private @Nullable ITmfStateSystem fStateSystem = null;

    private Map<Integer, Long> quarkToTimerDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TIMER = 7
    private Map<Integer, Long> quarkToTimerFreq = new HashMap<>();
    private Map<Integer, Long> quarkToTaskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_TASK = 6
    private Map<Integer, Long> quarkToTaskFreq = new HashMap<>();
    private Map<Integer, Long> quarkToDiskDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_DISK = 8
    private Map<Integer, Long> quarkToDiskFreq = new HashMap<>();
    private Map<Integer, Long> quarkToNetDuration = new HashMap<>(); //VCPU_STATUS_WAIT_FOR_NET = 9
    private Map<Integer, Long> quarkToNetFreq = new HashMap<>();
    private Map<Integer, Long> quarkToUnknownDuration = new HashMap<>(); //VCPU_STATUS_UNKNOWN = 0
    private Map<Integer, Long> quarkToUnknownFreq = new HashMap<>();
    private Map<Integer, Long> quarkToRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_ROOT = 1
    private Map<Integer, Long> quarkToRootFreq = new HashMap<>();
    private Map<Integer, Long> quarkToNonRootDuration = new HashMap<>(); //VCPU_STATUS_RUNNING_NON_ROOT = 2
    private Map<Integer, Long> quarkToNonRootFreq = new HashMap<>();
    private Map<Integer, Long> quarkToIdleDuration = new HashMap<>(); //? = 11
    private Map<Integer, Long> quarkToIdleFreq = new HashMap<>();

    static {
        REQUIREMENTS = checkNotNull(Collections.EMPTY_SET);
    }

    @SuppressWarnings({ "resource", "null" })
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

        //get all needed wait times for all processes
        List<Integer> quarks = fStateSystem.getQuarks("VMs","*","Process","*","Status");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
        checkNotNull(quarks);
        long start = fStateSystem.getStartTime();
        long end = fStateSystem.getCurrentEndTime();
        Iterable<ITmfStateInterval> iterable = null;
        try {
            iterable = fStateSystem.query2D(quarks, start, end);
        } catch (IndexOutOfBoundsException | TimeRangeException | StateSystemDisposedException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        long dur;
        long freq;
        for (ITmfStateInterval interval : iterable) {//iterate over all intervals and collect metrics
            Integer quark = interval.getAttribute();
            dur = interval.getEndTime()-interval.getStartTime();
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

            case 11: //Corresponds to FINISHED but can't find where this comes from @Hani: Any ideas?
                //I am guessing that this means the process is transitioned into an idle state
                if (quarkToIdleDuration.containsKey(quark)) {
                    dur += quarkToIdleDuration.get(quark);
                    freq = quarkToIdleFreq.get(quark);
                }
                else {
                    freq = 0;
                }
                quarkToIdleDuration.put(quark,dur);
                freq++;
                quarkToIdleFreq.put(quark,freq);
                break;

            default:
                //TODO throw some exception and provide error message here
                System.out.println("SateValue not recognized : "+interval.getStateValue().toString());
                break;
            }
        }

        //iterate over quarks and write vectors to files as follows:
        //avgdur.vector:    VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT,IDLE
        //frequency.vector: VMID/CR3,TIMER,DISK,NET,TASK,UNKNOWN,NON_ROOT,ROOT,IDLE

        String suppDir = TmfTraceManager.getSupplementaryFileDir(trace);
        String listFileName = suppDir + File.separator + ".." + File.separator + TRACE_FOLDER_LIST; //one level above

        try {
            Files.write(Paths.get(listFileName), (suppDir + System.lineSeparator()).getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (UnsupportedEncodingException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        } catch (IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        //if (!listFile.exists()) {
        //    dir.mkdirs();
        //}

        //System.out.println(suppDir);
        //open output file for storing feature vectors
        File fileAvg = null;
        File fileFreq = null;
        try {
            fileAvg = new File(suppDir+"avgdur.vector"); //$NON-NLS-1$
        } catch (Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            fileFreq = new File(suppDir+"frequency.vector"); //$NON-NLS-1$
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
        Long avgIdle;
        Long freqUnknown;
        Long freqRoot;
        Long freqNonRoot;
        Long freqDisk;
        Long freqNet;
        Long freqTimer;
        Long freqTask;
        Long freqIdle;
        for (Integer quark : quarks) {//iterate over quarks
            path = fStateSystem.getFullAttributePathArray(quark);
            key = path[1]+"/"+path[3];
            //compute average durations
            avgUnknown = 0L;
            freqUnknown = 0L;
            if (quarkToUnknownFreq.containsKey(quark)) {
                avgUnknown = quarkToUnknownDuration.get(quark) / quarkToUnknownFreq.get(quark);
                freqUnknown = quarkToUnknownFreq.get(quark);
            }
            avgRoot = 0L;
            freqRoot = 0L;
            if (quarkToRootFreq.containsKey(quark)) {
                avgRoot = quarkToRootDuration.get(quark) / quarkToRootFreq.get(quark);
                freqRoot = quarkToRootFreq.get(quark);
            }
            avgNonRoot = 0L;
            freqNonRoot = 0L;
            if (quarkToNonRootFreq.containsKey(quark)) {
                avgNonRoot = quarkToNonRootDuration.get(quark) / quarkToNonRootFreq.get(quark);
                freqNonRoot = quarkToNonRootFreq.get(quark);
            }
            avgDisk = 0L;
            freqDisk = 0L;
            if (quarkToDiskFreq.containsKey(quark)) {
                avgDisk = quarkToDiskDuration.get(quark) / quarkToDiskFreq.get(quark);
                freqDisk = quarkToDiskFreq.get(quark);
            }
            avgNet = 0L;
            freqNet = 0L;
            if (quarkToNetFreq.containsKey(quark)) {
                avgNet = quarkToNetDuration.get(quark) / quarkToNetFreq.get(quark);
                freqNet = quarkToNetFreq.get(quark);
            }
            avgTimer = 0L;
            freqTimer = 0L;
            if (quarkToTimerFreq.containsKey(quark)) {
                avgTimer = quarkToTimerDuration.get(quark) / quarkToTimerFreq.get(quark);
                freqTimer = quarkToTimerFreq.get(quark);
            }
            avgTask = 0L;
            freqTask = 0L;
            if (quarkToTaskFreq.containsKey(quark)) {
                avgTask = quarkToTaskDuration.get(quark) / quarkToTaskFreq.get(quark);
                freqTask = quarkToTaskFreq.get(quark);
            }
            avgIdle = 0L;
            freqIdle = 0L;
            if (quarkToIdleFreq.containsKey(quark)) {
                avgIdle = quarkToIdleDuration.get(quark) / quarkToIdleFreq.get(quark);
                freqIdle = quarkToIdleFreq.get(quark);
            }

            //store in file
            byte[] avgInBytes = (key+","+Long.toString(avgTimer)+","+
                                          Long.toString(avgDisk)+","+
                                          Long.toString(avgNet)+","+
                                          Long.toString(avgTask)+","+
                                          Long.toString(avgUnknown)+","+
                                          Long.toString(avgNonRoot)+","+
                                          Long.toString(avgRoot)+","+
                                          Long.toString(avgIdle)+"\n").getBytes();

            byte[] freqInBytes = (key+","+Long.toString(freqTimer)+","+
                                           Long.toString(freqDisk)+","+
                                           Long.toString(freqNet)+","+
                                           Long.toString(freqTask)+","+
                                           Long.toString(freqUnknown)+","+
                                           Long.toString(freqNonRoot)+","+
                                           Long.toString(freqRoot)+","+
                                           Long.toString(freqIdle)+"\n").getBytes();
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

        return true;
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
