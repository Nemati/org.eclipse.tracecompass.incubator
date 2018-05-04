package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmIdle;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.signals.TmfThreadSelectedSignal;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.exceptions.AttributeNotFoundException;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateSystemDisposedException;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisParamProvider;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalHandler;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalManager;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;


/**
 * @author Hani Nemati
 *
 */
public class vmIdleDetection extends TmfAbstractAnalysisParamProvider  {
    private static final String NAME = "Idle VM detection provider"; //$NON-NLS-1$
    private FileWriter fFw;
    private PrintWriter fOut;
    private Long sumThreadUsage;
    private String processName2Detect;
    Long beginTS ;

    Long endTS ;
    private class patternFrequent {
        public Vector<Long> time = new Vector<>(2);
        public Vector<Long> timeToFinish = new Vector<>(2);
        public String pattern;
        public Long frequency;

        public void setFreq(Long freq) {
            this.frequency = freq;
        }
        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

    }
    /**
     *
     */
    public vmIdleDetection() {

        super();
        TmfSignalManager.register(this);
    }

    /**
     * Update the view when a thread is selected
     *
     * @param signal
     *            The thread selected signal
     */
    @TmfSignalHandler
    public void threadSelected(TmfThreadSelectedSignal signal) {
        //int threadId = signal.getThreadId();
    }

    public void idleVMDetection(ITmfStateSystem ss) throws AttributeNotFoundException, StateSystemDisposedException {
        System.out.println("Started");


            //ITmfStateSystem ss = TmfStateSystemAnalysisModule.getStateSystem(threadSignal.getTrace(), KernelAnalysisModule.ID);
            List<Integer> machinesQuarks = ss.getQuarks("Threads", "*"); //$NON-NLS-1$ //$NON-NLS-2$
            ArrayList<String> exeptionsProgram=new ArrayList<>();
            File execptionFile = new File("exeption_list.txt"); //$NON-NLS-1$
            BufferedReader signatureReader ;

            try {
                signatureReader = new BufferedReader(new FileReader(execptionFile));
                String text = null;

                while ((text = signatureReader.readLine()) != null) {
                    exeptionsProgram.add(text);
                }
                signatureReader.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            processName2Detect = "0";
            for (int quark : machinesQuarks) {


                    boolean lastExeption = false;



                    if(ss.getAttributeName(quark).toString().equals("-1")){
                        continue;
                    }
                    int nameQuark = ss.getQuarkRelative(quark, "Exec_name"); //$NON-NLS-1$
                    Long ts = ss.getCurrentEndTime();
                    ITmfStateInterval nameCurrentInterval = ss.querySingleState(ts, nameQuark);
                    String processName = nameCurrentInterval.getValue().toString();
                    if (processName.equals("nginx")||processName.equals("mysqld")||processName.equals("mongod")||processName.equals("sshd")||processName.equals("bash")) {
                    if(processName.contains("swapper")) {
                        continue;
                    }

                    int PPIDQuark = ss.getQuarkRelative(quark, "PPID"); //$NON-NLS-1$

                    ITmfStateInterval PPIDCurrentInterval = ss.querySingleState(ts, PPIDQuark);

                    if(exeptionsProgram.contains(nameCurrentInterval.getValue().toString())) {
                        continue;
                    }
                    if(PPIDCurrentInterval.getValue().toString().equals("2")) { //$NON-NLS-1$
                        continue;
                    }
                    for (String s:exeptionsProgram) {
                        if(nameCurrentInterval.getValue().toString().contains(s)) {
                            lastExeption = true;
                            break;
                        }
                    }
                    if (lastExeption) {
                        continue;
                    }
                    System.out.println("Finding Frequent Pattern for:" +nameCurrentInterval.getValue()+"   PID:"+ ss.getAttributeName(quark)); //$NON-NLS-1$
                    try {
                        findFrequentPattern(ss, quark);
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }

            }
            }
            System.out.println("*********************Done *************************");


    }

    @TmfSignalHandler
    public void tmfThreadSelectedSignalHander(TmfThreadSelectedSignal signal) throws AttributeNotFoundException, IOException, StateSystemDisposedException {
        System.out.println("Started");
        final TmfThreadSelectedSignal threadSignal = signal;
        if (threadSignal != null) {
            Iterator<@NonNull KernelAnalysisModule> kernelModules = TmfTraceUtils.getAnalysisModulesOfClass(threadSignal.getHostId(), KernelAnalysisModule.class).iterator();
            if (!kernelModules.hasNext()) {
                return;
            }
            KernelAnalysisModule module = kernelModules.next();
            ITmfStateSystem ss = module.getStateSystem();
            List<Integer> machinesQuarks = ss.getQuarks("Threads", "*"); //$NON-NLS-1$ //$NON-NLS-2$
            ArrayList<String> exeptionsProgram=new ArrayList<>();
            File execptionFile = new File("exeption_list.txt"); //$NON-NLS-1$
            BufferedReader signatureReader ;

            try {
                signatureReader = new BufferedReader(new FileReader(execptionFile));
                String text = null;

                while ((text = signatureReader.readLine()) != null) {
                    exeptionsProgram.add(text);
                }
                signatureReader.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            processName2Detect = "0";
            for (int quark : machinesQuarks) {
                if (ss.getAttributeName(quark).equals(Integer.toString(threadSignal.getThreadId()))) {
                    boolean lastExeption = false;
                    if (ss.getAttributeName(quark).equals(Integer.toString(threadSignal.getThreadId()))) {
                        int nameQuark = ss.getQuarkRelative(quark, "Exec_name"); //$NON-NLS-1$
                        Long ts = ss.getCurrentEndTime();
                        ITmfStateInterval nameCurrentInterval = ss.querySingleState(ts, nameQuark);
                        processName2Detect = nameCurrentInterval.getValue().toString();
                    }

                    if(ss.getAttributeName(quark).toString().equals("-1")){
                        continue;
                    }
                    int nameQuark = ss.getQuarkRelative(quark, "Exec_name"); //$NON-NLS-1$
                    Long ts = ss.getCurrentEndTime();
                    ITmfStateInterval nameCurrentInterval = ss.querySingleState(ts, nameQuark);
                    String processName = nameCurrentInterval.getValue().toString();
                    if(processName.contains("swapper")) {
                        continue;
                    }
                    if(!processName.contains(processName2Detect)) {
                        continue;
                    }
                    int PPIDQuark = ss.getQuarkRelative(quark, "PPID"); //$NON-NLS-1$

                    ITmfStateInterval PPIDCurrentInterval = ss.querySingleState(ts, PPIDQuark);

                    if(exeptionsProgram.contains(nameCurrentInterval.getValue().toString())) {
                        continue;
                    }
                    if(PPIDCurrentInterval.getValue().toString().equals("2")) { //$NON-NLS-1$
                        continue;
                    }
                    for (String s:exeptionsProgram) {
                        if(nameCurrentInterval.getValue().toString().contains(s)) {
                            lastExeption = true;
                            break;
                        }
                    }
                    if (lastExeption) {
                        continue;
                    }
                    System.out.println("Finding Frequent Pattern for:" +nameCurrentInterval.getValue()+"   PID:"+ ss.getAttributeName(quark)); //$NON-NLS-1$
                    try {
                        findFrequentPattern(ss, quark);
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }
            System.out.println("*********************Done *************************");
        }
    }
    public boolean findFrequentPattern(ITmfStateSystem ss, int quark) throws AttributeNotFoundException, IOException{
        sumThreadUsage = 0L;
        HashMap<String,patternFrequent> newfrequency = new HashMap<>();
        TreeMap<Integer, Integer> threadSyscallHolder = new TreeMap();
        int lineNumber = 1;
        int syscallLineNumber = 1;
        ///   Read Syscall from File //////////////////////////////
        HashMap<Integer,String> syscallMapL2S = new HashMap<>(); // Line to String
        HashMap<String,Integer> syscallMapS2L = new HashMap<>();
        File syscallFile = new File("syscallFile.txt"); //$NON-NLS-1$
        BufferedReader syscallReader ;

        try {
            syscallReader = new BufferedReader(new FileReader(syscallFile));
            String text = null;

            while ((text = syscallReader.readLine()) != null) {
                syscallMapL2S.put(syscallLineNumber, text);
                syscallMapS2L.put(text,syscallLineNumber);
                syscallLineNumber++;

            }
            syscallReader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


        //// Read Signature from File /////////////////////////////
        HashMap<Integer,String> signatureMapL2S = new HashMap<>(); // Line to String
        HashMap<String,Integer> signatureMapS2L = new HashMap<>();
        File signatureFile = new File("signature.txt"); //$NON-NLS-1$
        BufferedReader signatureReader ;
        TreeMap<Integer, String> threadSignatureHolder = new TreeMap();
        try {
            signatureReader = new BufferedReader(new FileReader(signatureFile));
            String text = null;

            while ((text = signatureReader.readLine()) != null) {
                signatureMapL2S.put(lineNumber, text);
                signatureMapS2L.put(text,lineNumber);
                lineNumber++;

            }
            signatureReader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }



        ///////////////////////////////////////////////////////////////////////////
        if (ss != null) {
            beginTS = Math.max(0, ss.getStartTime());
            Long timeToFinish = 0L;
            endTS =  ss.getCurrentEndTime();
            if (beginTS > endTS) {
                return false;
            }
            try {






                //////////////////////////////////////////////////////////////////////////////
                ITmfStateInterval currentInterval = ss.querySingleState(beginTS, quark);
                boolean lastStateBlock = true;
                /* Get the following state changes */
                long ts = currentInterval.getEndTime();
                String pattern= new String();
                while (ts != -1 && ts < endTS) {
                    ts++; /* To "jump over" to the next state in the history */
                    currentInterval = ss.querySingleState(ts, quark);
                    if (currentInterval.getValue().toString().equals("3")) { // syscall
                        int system_call = ss.getQuarkRelative(quark, "System_call");
                        ITmfStateInterval sysCurrentInterval = ss.querySingleState(ts, system_call);
                        String syscallName = sysCurrentInterval.getValue().toString();
                        ///// Add new syscall to list ////////////////////////////


                        if (!syscallMapS2L.containsKey(syscallName)) {
                            syscallMapL2S.put(syscallLineNumber, syscallName);
                            syscallMapS2L.put(syscallName,syscallLineNumber);
                            syscallLineNumber++;
                            fOut = null;
                            BufferedWriter bw = null;
                            fFw = null;
                            try{
                                fFw = new FileWriter("syscallFile.txt", true);
                                bw = new BufferedWriter(fFw);
                                fOut = new PrintWriter(bw);
                                fOut.println(syscallName);
                                fOut.close();
                            } finally {
                                if(fOut != null) {
                                    fOut.close();
                                }
                                try {
                                    if(bw != null) {
                                        bw.close();
                                    }
                                } catch (IOException e) {
                                    //exception handling left as an exercise for the reader
                                }
                                try {
                                    if(fFw != null) {
                                        fFw.close();
                                    }
                                } catch (IOException e) {
                                    //exception handling left as an exercise for the reader
                                }
                            }
                        }
                        threadSyscallHolder.put(syscallMapS2L.get(syscallName), 1);
                        //////////////////////////////////////////////////////////

                        if (lastStateBlock == true) {
                            lastStateBlock = false ;
                            timeToFinish = ts;
                            pattern += syscallName;
                        } else {
                            pattern += ","+syscallName;
                        }
                        if(syscallName.equals("syscall_entry_exit_group")||syscallName.equals("syscall_entry_exit")) {
                            ///////////////////////////////////////////////////////////////////////////////////////////////
                            //pattern = "UserSpace";
                            if (newfrequency.containsKey(pattern)) {
                                patternFrequent patternClass = newfrequency.get(pattern);
                                Long freq = patternClass.frequency+1;
                                patternClass.setFreq(freq);
                                patternClass.time.addElement(ts);
                                patternClass.timeToFinish.addElement(ts-timeToFinish);
                            } else {
                                patternFrequent patternClass = new patternFrequent();
                                patternClass.setFreq(1L);
                                patternClass.setPattern(pattern);
                                patternClass.time.addElement(ts);
                                patternClass.timeToFinish.addElement(ts-timeToFinish);
                                newfrequency.put(pattern,patternClass);
                            }
                            pattern = "";
                            lastStateBlock = true ;
                            break;
                        }
                    } else if (currentInterval.getValue().toString().equals("2")) { // userspace
                        if (lastStateBlock == true) {
                            lastStateBlock = false ;
                            pattern += "UserSpace";
                            timeToFinish = ts;
                        } else {
                            pattern += ",UserSpace";
                        }
                    } else if (currentInterval.getValue().toString().equals("1")) { // block
                        ///////////////////////////////////////////////////////////////////////////////////////////////

                        if (newfrequency.containsKey(pattern)) {
                            patternFrequent patternClass = newfrequency.get(pattern);
                            Long freq = patternClass.frequency+1;
                            patternClass.setFreq(freq);
                            patternClass.time.addElement(ts);
                            patternClass.timeToFinish.addElement(ts-timeToFinish);
                        } else {
                            patternFrequent patternClass = new patternFrequent();
                            patternClass.setFreq(1L);
                            patternClass.setPattern(pattern);
                            patternClass.time.addElement(ts);
                            patternClass.timeToFinish.addElement(ts-timeToFinish);
                            newfrequency.put(pattern,patternClass);
                        }
                        pattern = "";
                        lastStateBlock = true ;
                    }
                    ts = currentInterval.getEndTime();
                }
            } catch (StateSystemDisposedException e) {
                /* Ignore ... */
            }
        }
        Iterator it = newfrequency.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            patternFrequent patternClass = (patternFrequent) pair.getValue();
            if (patternClass.frequency > 0) {
                Enumeration en = patternClass.time.elements(); // for mean
                Enumeration en1 = patternClass.time.elements(); // for variance
                Long mean = getMean(en);
                double variance = getVariance(en1,mean);
                String patternString = String.format("%.12f",(float)patternClass.frequency/((float)(endTS-beginTS)));
                if (signatureMapS2L.containsKey(patternClass.pattern)) {
                    System.out.println("S"+signatureMapS2L.get(patternClass.pattern)+":"+patternClass.pattern + " = " +  patternClass.frequency);
                } else {
                    fOut = null;
                    BufferedWriter bw = null;
                    fFw = null;
                    try{
                        fFw = new FileWriter("signature.txt", true);
                        bw = new BufferedWriter(fFw);
                        fOut = new PrintWriter(bw);
                        fOut.println(patternClass.pattern);
                        signatureMapL2S.put(lineNumber, patternClass.pattern);
                        signatureMapS2L.put(patternClass.pattern, lineNumber);
                        System.out.println("S"+signatureMapS2L.get(patternClass.pattern)+":"+patternClass.pattern + " = " +  patternClass.frequency);
                        lineNumber++;
                        fOut.close();
                    } finally {
                        if(fOut != null) {
                            fOut.close();
                        }
                        try {
                            if(bw != null) {
                                bw.close();
                            }
                        } catch (IOException e) {
                            //exception handling left as an exercise for the reader
                        }
                        try {
                            if(fFw != null) {
                                fFw.close();
                            }
                        } catch (IOException e) {
                            //exception handling left as an exercise for the reader
                        }
                    }
                }

                System.out.println("Freq ---> Mean:"+mean +" ns "+"  Variance:"+variance +"  Coefficient of variation:"+variance/mean);
                if (variance > 0.0) {
                    patternString +=","+String.format("%.12f",variance/mean);
                } else {
                    patternString +=",0.0";
                }
                en = patternClass.timeToFinish.elements();
                en1 = patternClass.timeToFinish.elements();
                mean = getMeanNormal(en);
                sumThreadUsage += mean*patternClass.frequency;
                variance = getVarianceNormal(en1,mean);
                System.out.println("ElapsedTime ---> Mean:"+mean +" ns "+"  Variance:"+variance +"  Coefficient of variation:"+variance/mean);
                patternString += ","+mean.toString()+","+String.format("%.12f",100*mean*patternClass.frequency/(float)(endTS-beginTS));
                threadSignatureHolder.put(signatureMapS2L.get(patternClass.pattern),patternString) ;
            }
            it.remove(); // avoids a ConcurrentModificationException
        }
        System.out.println("Total CPU Usage For Thread:"+sumThreadUsage+"    Percentage:"+((float)sumThreadUsage/(float)(endTS-beginTS))*100);
        System.out.println(threadSignatureHolder);
        System.out.println(syscallMapL2S);
        System.out.println("------------------------------------------------------------------------");

        if (!threadSignatureHolder.isEmpty()) {
            fOut = null;
            BufferedWriter bw = null;
            fFw = null;
            try{
                // If you want to add more train data just rename it to patternData.txt and change false value to true to append
                fFw = new FileWriter("patternData.txt", true);
                bw = new BufferedWriter(fFw);
                fOut = new PrintWriter(bw);
                // One means IDLE
                String what2writeInDataFile = "0,"+String.format("%.12f",(((float)sumThreadUsage/(float)(endTS-beginTS))*100))+",";
                Iterator iterate = threadSignatureHolder.entrySet().iterator();
                Integer sig = 1;
                while (iterate.hasNext()) {
                    Map.Entry pair = (Map.Entry)iterate.next();
                    Integer key = (Integer) pair.getKey();
                    if (key > sig) {
                        Integer diff = key- sig ;
                        for (int i = 1;i<diff;i++) {
                            what2writeInDataFile += "0,0.0,0.0,0,0.0,";
                        }
                        sig = key;
                        what2writeInDataFile+="1,"+pair.getValue()+",";
                    }
                    iterate.remove(); // avoids a ConcurrentModificationException
                }
                for (int i = sig;i<lineNumber;i++) {
                    what2writeInDataFile += "0,0.0,0.0,0,0.0,";
                }
                what2writeInDataFile += "0,0.0,0.0,0,0.0";
                fOut.println(what2writeInDataFile);


                fOut.close();
            } finally {
                if(fOut != null) {
                    fOut.close();
                }
                try {
                    if(bw != null) {
                        bw.close();
                    }
                } catch (IOException e) {
                    //exception handling left as an exercise for the reader
                }
                try {
                    if(fFw != null) {
                        fFw.close();
                    }
                } catch (IOException e) {
                    //exception handling left as an exercise for the reader
                }
            }
        }
        if (!threadSyscallHolder.isEmpty()) {
        String textToWriteInSyscallFile = "" ;
        System.out.println(threadSyscallHolder);
        it = threadSyscallHolder.entrySet().iterator();
        Integer sig = 0;
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            Integer key = (Integer) pair.getKey();
            if (key > sig) {
                Integer diff = key- sig ;
                for (int j = 1;j<diff;j++) {
                    textToWriteInSyscallFile += "0,";
                }
                sig = key;
                textToWriteInSyscallFile+="1,";
            }
            it.remove(); // avoids a ConcurrentModificationException
        }
        for (int k = sig;k<300;k++) {
            textToWriteInSyscallFile += "0,";
        }
        textToWriteInSyscallFile+="0";
        System.out.println(textToWriteInSyscallFile);
        // write to syscall feature

        /* Save the threadID *//////////////////////////////////////////////////////////
        String threadPID = ss.getAttributeName(quark);
        if (!threadPID.isEmpty()) {
            fOut = null;
            BufferedWriter bw = null;
            fFw = null;
            try{
                // If you want to add more train data just rename it to patternData.txt and change false value to true to append
                fFw = new FileWriter("threads.txt", true);
                bw = new BufferedWriter(fFw);
                fOut = new PrintWriter(bw);
                // One means IDLE

                fOut.println(threadPID);


                fOut.close();
            } finally {
                if(fOut != null) {
                    fOut.close();
                }
                try {
                    if(bw != null) {
                        bw.close();
                    }
                } catch (IOException e) {
                    //exception handling left as an exercise for the reader
                }
                try {
                    if(fFw != null) {
                        fFw.close();
                    }
                } catch (IOException e) {
                    //exception handling left as an exercise for the reader
                }
            }
        }

        {
        fOut = null;
        BufferedWriter bw = null;
        fFw = null;
        try{
            fFw = new FileWriter("syscallFeatures.txt", true);
            bw = new BufferedWriter(fFw);
            fOut = new PrintWriter(bw);
            fOut.println(textToWriteInSyscallFile);

            fOut.close();
        } finally {
            if(fOut != null) {
                fOut.close();
            }
            try {
                if(bw != null) {
                    bw.close();
                }
            } catch (IOException e) {
                //exception handling left as an exercise for the reader
            }
            try {
                if(fFw != null) {
                    fFw.close();
                }
            } catch (IOException e) {
                //exception handling left as an exercise for the reader
            }
        }

        }
        }
        return true;
    }
    public Long getMeanNormal (Enumeration en) {
        Long sum = 0L;
        int i = 0;

        while(en.hasMoreElements()) {
            sum += (Long)en.nextElement();
            i++;
        }
        if (i>0) {
            return sum/i;
        }
        return 0L;
    }
    public double getVarianceNormal (Enumeration en, Long mean) {
        double sum = 0L;
        int i = 0;
        while(en.hasMoreElements()) {
            Long elementTime = (Long)en.nextElement();
            sum += (elementTime-mean)*(elementTime-mean);
            i++;
        }
        if (i>0) {
            return Math.sqrt(sum)/i;
        }
        return 0L;
    }
    public Long getMean( Enumeration en) {
        Long lastTs = 0L;
        Long sum = 0L;
        int i = 0;
        while(en.hasMoreElements()) {
            Long elementTime = (Long)en.nextElement();
            if (lastTs > 0L) {
                sum += elementTime-lastTs;
                i++;
            }
            lastTs = elementTime;
        }
        if (i>0) {
            return sum/i;
        }
        return 0L;
    }
    public double getVariance(Enumeration en, Long mean) {
        Long lastTs = 0L;
        double sum = 0L;
        int i = 0;
        while(en.hasMoreElements()) {
            Long elementTime = (Long)en.nextElement();
            if (lastTs > 0L) {
                sum += (elementTime-lastTs-mean)*(elementTime-lastTs-mean);
                i++;
            }
            lastTs = elementTime;
        }
        if (i>0) {
            return Math.sqrt(sum)/i;
        }
        return 0L;
    }

    @Override
    public String getName() {
        return NAME;
    }
    @Override
    public Object getParameter(String name) {
        // TODO Auto-generated method stub
        return null;
    }
    @Override
    public boolean appliesToTrace(ITmfTrace trace) {
        // TODO Auto-generated method stub
        return false;
    }
}
