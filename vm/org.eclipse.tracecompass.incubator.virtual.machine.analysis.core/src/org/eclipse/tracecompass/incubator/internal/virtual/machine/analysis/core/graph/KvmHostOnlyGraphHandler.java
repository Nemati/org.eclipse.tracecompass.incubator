package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.graph;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.tracecompass.analysis.graph.core.base.TmfGraph;
import org.eclipse.tracecompass.analysis.graph.core.base.TmfVertex;
import org.eclipse.tracecompass.analysis.graph.core.base.TmfEdge.EdgeType;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfGraph;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfVertex;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfEdge.EdgeType;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfGraph;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfVertex;
//import org.eclipse.tracecompass.analysis.graph.core.base.TmfEdge.EdgeType;
import org.eclipse.tracecompass.analysis.graph.core.building.AbstractTraceEventHandler;
import org.eclipse.tracecompass.analysis.graph.core.building.ITraceEventHandler;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.IOsExecutionGraphHandlerBuilder;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsExecutionGraphProvider;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsWorker;
import org.eclipse.tracecompass.analysis.os.linux.core.model.HostThread;
import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
import org.eclipse.tracecompass.common.core.NonNullUtils;
//import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsWorker;
//import org.eclipse.tracecompass.analysis.os.linux.core.model.HostThread;
//import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
//import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsWorker;
//import org.eclipse.tracecompass.analysis.os.linux.core.model.HostThread;
//import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
//import org.eclipse.tracecompass.common.core.NonNullUtils;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.VMblockAnalysis;
//import org.eclipse.tracecompass.internal.analysis.os.linux.core.kernel.Attributes;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateSystemDisposedException;
import org.eclipse.tracecompass.statesystem.core.exceptions.TimeRangeException;

//import org.eclipse.tracecompass.tmf.core.analysis.IAnalysisModule;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

public class KvmHostOnlyGraphHandler extends AbstractTraceEventHandler {
    private static Map<Integer, criticalVMclass> pid2VM = new HashMap<>();
    private static Map<Integer,Integer> tid2pid = new HashMap<>();
    private final OsExecutionGraphProvider fProvider;
    private VMblockAnalysis fVmBlock;
    private int times;

    public KvmHostOnlyGraphHandler(OsExecutionGraphProvider provider, int priority) {
        super(priority);
        times = 1;
        fProvider = provider;
        VMblockAnalysis vmBlock = TmfTraceUtils.getAnalysisModuleOfClass(provider.getTrace(), VMblockAnalysis.class, VMblockAnalysis.ID);
        if (vmBlock == null) {
            throw new NullPointerException("This shouldn't be, Why not?");
        }
        fVmBlock = vmBlock;
    }

    /**
     * The handler builder for the event context handler
     */
    public static class HandlerBuilderKvmHostOnly implements IOsExecutionGraphHandlerBuilder {

        @Override
        public ITraceEventHandler createHandler(OsExecutionGraphProvider provider, int priority) {
            return new KvmHostOnlyGraphHandler(provider, priority);
        }

    }

    @Override
    public void handleEvent(ITmfEvent event) {
        if (event.getName().equals("addons_vcpu_enter_guest")) {
            handleVcpuEnterGuest(event);

        } else if (event.getName().equals("kvm_inj_virq")) {
            handleKvmInjVirq(event);

        } else if (event.getName().equals("sched_ttwu")) {
            handleSchedTtwu(event);
        } else if (event.getName().equals("sched_switch")) {
            handleSchedSwitch(event);
        } else if (event.getName().equals("kvm_exit")) {
            handleKvmExit(event);
        }

        // Do you consider the event^ Is the name of the event in a list of useful events
        // Read data for VM from StateHistory Tree
        if (times ==1) {
            VMblockAnalysis vmBlock = fVmBlock;
            ITmfStateSystem stateSystem = vmBlock.getStateSystem();
            if (stateSystem == null) {
                throw new NullPointerException("This shouldn't be, Why not?");
            }
            //TmfGraph graph = NonNullUtils.checkNotNull(fProvider.getAssignedGraph());
            //Long start = stateSystem.getStartTime();
            List<Integer> VMsQuarks = new ArrayList<>(stateSystem.getQuarks("VMs", "*"));
            //quarks.addAll(stateSystem.getQuarks(Attributes.THREADS, WILDCARD, Attributes.PPID));
            System.out.println(VMsQuarks);
            for (int VMsQuark:VMsQuarks) {
                try {
                    Integer VMname = Integer.valueOf(stateSystem.getAttributeName(VMsQuark));
                    System.out.println(VMname);
                    criticalVMclass vm1 = new criticalVMclass(VMname);
                    List<Integer> processQuarks = new ArrayList<>(stateSystem.getQuarks("VMs", VMname.toString(),"Process","*"));

                    for (int processQuark:processQuarks) {
                        String processCr3 = stateSystem.getAttributeName(processQuark);
                        if(!processCr3.equals("0")) {
                            Integer processftid = Integer.valueOf(stateSystem.querySingleState(stateSystem.getCurrentEndTime(),processQuark).getValue().toString());
                            vm1.setFtid(processCr3, processftid);
                        }
                    }
                    List<Integer> irqQuarks = new ArrayList<>(stateSystem.getQuarks("VMs", VMname.toString(),"irq","*"));
                    System.out.println(irqQuarks);
                    for (int irqQuark:irqQuarks) {
                        String irqName = stateSystem.getAttributeName(irqQuark).toString();


                        Integer irqNumber = Integer.valueOf(stateSystem.querySingleState(stateSystem.getCurrentEndTime(),irqQuark).getValue().toString());
                        if (irqName.equals("net")) {
                            vm1.setNetworkIRQ(irqNumber);
                        } else if (irqName.equals("disk")) {
                            vm1.setDiskIRQ(irqNumber);
                        }
                    }
                    System.out.println(VMname +":"+vm1.getNetworkIRQ());
                    pid2VM.put(VMname, vm1);
                } catch (IndexOutOfBoundsException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (TimeRangeException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (StateSystemDisposedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
            // Get the worker to be woken
            //OsWorker wakee = getOrCreateKernelWorker(something, something);
            //TmfGraph graph = NonNullUtils.checkNotNull(fProvider.getAssignedGraph());
            // Add a blocked transition to that wakee
            //TmfVertex wakeeVertex = new TmfVertex(ts);
            // Append a state to that worker
            //graph.append(wakee, wakeeVertex, EdgeType.BLOCKED);

            // If you have a dependency to add
            // Get the other worker
            //OsWorker waker = getOrCreateKernelWorker(something, somethingelse);

            //TmfVertex wakerVertex = new TmfVertex(ts);
            // Add state to waker
            //graph.append(wakee, wakeeVertex, EdgeType.BLOCK_DEVICE);

            // Add the link from waker to wakk
            //wakerVertex.linkVertical(wakeeVertex);
        }
        times++;
    }

    private OsWorker getOrCreateKernelWorker(Integer vm, Integer tid, Long ts) {
        // The host ID should be unique for a VM
        // The tid is an integer, you can use a map from the VM, CR3 to an Integer
        HostThread ht = new HostThread(vm.toString(), tid);
        OsWorker worker = fProvider.getSystem().findWorker(ht);
        if (worker != null) {
            return worker;
        }
        //"kernel/" + tid This is the name of the process/tid, what will appear on left of the critical path view, I think you can set it on a worker later too
        worker = new OsWorker(ht, "VMkernel/" + tid, ts); //$NON-NLS-1$
        worker.setStatus(ProcessStatus.RUN);
        fProvider.getSystem().addWorker(worker);
        return worker;
    }
    private OsWorker getOrCreateKernelWorker(String vm, Integer tid, Long ts) {
        // The host ID should be unique for a VM
        // The tid is an integer, you can use a map from the VM, CR3 to an Integer
        HostThread ht = new HostThread(vm, tid);
        OsWorker worker = fProvider.getSystem().findWorker(ht);
        if (worker != null) {
            return worker;
        }
        //"kernel/" + tid This is the name of the process/tid, what will appear on left of the critical path view, I think you can set it on a worker later too
        worker = new OsWorker(ht, "VMkernel/" + tid, ts); //$NON-NLS-1$
        worker.setStatus(ProcessStatus.RUN);
        fProvider.getSystem().addWorker(worker);
        return worker;
    }
    private static void handleKvmExit(ITmfEvent event) {
        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long exitReason = checkNotNull((Long)content.getField("exit_reason").getValue()); //$NON-NLS-1$
        Integer vcpu = pid2VM.get(pid.intValue()).getVcpu(tid.intValue());
        pid2VM.get(pid.intValue()).setVcpu2exit(vcpu, exitReason.intValue());
    }

    private void handleSchedSwitch(ITmfEvent event) {
        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }
        final long ts = event.getTimestamp().getValue();

        ITmfEventField content = event.getContent();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        //Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long prevTid = checkNotNull((Long)content.getField("prev_tid").getValue()); //$NON-NLS-1$
        Long nextTid = checkNotNull((Long)content.getField("next_tid").getValue()); //$NON-NLS-1$
        if (tid2pid.containsKey(prevTid.intValue())) {

            int vcpu = pid2VM.get(pid.intValue()).getVcpu(prevTid.intValue());
            //String lastCr3 = pid2VM.get(pid.intValue()).getCr3(vcpu);
            //int ftid = pid2VM.get(pid.intValue()).getFtid(lastCr3);
            String cr3 = pid2VM.get(pid.intValue()).getCr3(vcpu);
            int ftid = pid2VM.get(pid.intValue()).getFtid(cr3);
            Integer lastExit = pid2VM.get(pid.intValue()).getExit(vcpu);
            // It is being preempted
            if (!lastExit.equals(12)) {
                pid2VM.get(pid.intValue()).setCr3(vcpu, "1");
            }
            OsWorker schedOutWorker = getOrCreateKernelWorker(pid.intValue(), ftid , ts);
            TmfVertex schedOutVertex = new TmfVertex(ts);
            TmfGraph graph = NonNullUtils.checkNotNull(fProvider.getAssignedGraph());
            graph.append(schedOutWorker, schedOutVertex, EdgeType.RUNNING);

            //System.out.println("sched_in:"+schedOutWorker);
        }
        if (tid2pid.containsKey(nextTid.intValue())) {
            Integer nextPid = tid2pid.get(nextTid.intValue()).intValue();
            int vcpu = pid2VM.get(nextPid).getVcpu(nextTid.intValue());
            String cr3 = pid2VM.get(nextPid).getCr3(vcpu);

            if (!cr3.equals("1")) {
                pid2VM.get(nextPid).setCr3(vcpu, "0");
            }

        }


    }
    private static void handleSchedTtwu(ITmfEvent event) {


        ITmfEventField content = event.getContent();

        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        // tid is the one who wake up (waker)
        Long wakerTid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        // wtid is the one who is going to wake up (wakee)
        Long wakeeTid =  checkNotNull((Long)content.getField("tid").getValue()); //$NON-NLS-1$

        Long wakeePid = 0L;
        if(tid2pid.containsKey(wakeeTid.intValue())) {
            wakeePid = tid2pid.get(wakeeTid.intValue()).longValue();
        }
        if (!pid.equals(0L)) {
            if (tid2pid.containsKey(wakerTid.intValue()) && tid2pid.containsKey(wakeeTid.intValue())) {
                Integer vcpuWakee =  pid2VM.get(wakeePid.intValue()).getVcpu(wakeeTid.intValue());
                Integer vcpuWaker = pid2VM.get(pid.intValue()).getVcpu(wakerTid.intValue());

                String cr3 = pid2VM.get(pid.intValue()).getCr3(vcpuWaker);
                //Integer ftid = pid2VM.get(pid.intValue()).getFtid(cr3);
                pid2VM.get(wakeePid.intValue()).setWakee(vcpuWakee,pid,cr3);

            }
        }

    }

    private void handleKvmInjVirq(ITmfEvent event) {
        // TODO Auto-generated method stub
        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }

        ITmfEventField content = event.getContent();
        final long ts = event.getTimestamp().getValue();
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        Long irq = checkNotNull((Long)content.getField("irq").getValue()); //$NON-NLS-1$
        TmfGraph graph = NonNullUtils.checkNotNull(fProvider.getAssignedGraph());
        Integer vcpu = pid2VM.get(pid.intValue()).getVcpu(tid.intValue());
        String lastCr3 = pid2VM.get(pid.intValue()).getCr3(vcpu);
        Integer ftid =  pid2VM.get(pid.intValue()).getFtid(lastCr3);

        Integer diskIrq = pid2VM.get(pid.intValue()).getDiskIRQ();
        Integer netIrq = pid2VM.get(pid.intValue()).getNetworkIRQ();
        if (pid2VM.get(pid.intValue()).getAcceptIrq(lastCr3).equals(1)) {
            if (irq.equals(239L)) {
                // Timer

                OsWorker wakeup = getOrCreateKernelWorker(pid.intValue(), ftid, ts);

                TmfVertex timerVertex = new TmfVertex(ts);
                // Append a state to that worker
                graph.append(wakeup, timerVertex, EdgeType.TIMER);
                //System.out.println("timer:"+wakeup);

            } else if (irq.equals(251L) || irq.equals(252L)|| irq.equals(253L)) {
                //task
                // Read who wants to wake up this vcpu

                String wakerCr3 = pid2VM.get(pid.intValue()).getWakee(vcpu).getCr3();
                Long wakerPid = pid2VM.get(pid.intValue()).getWakee(vcpu).getPid();

                if (!wakerPid.equals(pid)) {
                    System.out.println("Wakerpid:"+wakerPid+":"+pid);
                }
                if (!wakerCr3.equals(lastCr3) && !wakerCr3.equals("0")) {

                    TmfVertex wakeeVertex = new TmfVertex(ts);
                    TmfVertex wakerVertex = new TmfVertex(ts);

                    Integer callerFtid = pid2VM.get(wakerPid.intValue()).getFtid(wakerCr3);

                    OsWorker wakee = getOrCreateKernelWorker(pid.intValue(), ftid, ts);
                    OsWorker waker = getOrCreateKernelWorker(wakerPid.intValue(), callerFtid, ts);

                    graph.append(wakee, wakeeVertex, EdgeType.BLOCKED);
                    graph.append(waker, wakerVertex, EdgeType.RUNNING);

                    wakerVertex.linkVertical(wakeeVertex);
                }

            }
            if (irq.equals(netIrq.longValue())) {
                // Network
                OsWorker wakeup = getOrCreateKernelWorker(pid.intValue(), ftid, ts);
                TmfVertex networkVertex = new TmfVertex(ts);
                // Append a state to that worker
                graph.append(wakeup, networkVertex, EdgeType.NETWORK);
                // System.out.println("net:"+wakeup);

            }
            if (irq.equals(diskIrq.longValue())) {
                // Disk
                OsWorker wakeup = getOrCreateKernelWorker(pid.intValue(), ftid, ts);
                TmfVertex diskVertex = new TmfVertex(ts);
                // Append a state to that worker
                graph.append(wakeup, diskVertex, EdgeType.BLOCK_DEVICE);
                //System.out.println("disk:"+wakeup);
            }
        } // end of {if (pid2VM.get(pid.intValue()).getAcceptIrq(lastCr3).equals(1))}
    }

    private void handleVcpuEnterGuest(ITmfEvent event) {
        // TODO Auto-generated method stub
        final long ts = event.getTimestamp().getValue();

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            return;
        }

        ITmfEventField content = event.getContent();
        Long vCPU_ID = checkNotNull((Long)content.getField("vcpuID").getValue()); //$NON-NLS-1$
        String cr3 = checkNotNull(content.getField("cr3tmp").getValue().toString()); //$NON-NLS-1$
        Long pid = checkNotNull((Long)content.getField("context._pid").getValue()); //$NON-NLS-1$
        Long tid = checkNotNull((Long)content.getField("context._tid").getValue()); //$NON-NLS-1$
        TmfGraph graph = NonNullUtils.checkNotNull(fProvider.getAssignedGraph());


        if (!tid2pid.containsKey(tid.intValue())) {
            tid2pid.put(tid.intValue(), pid.intValue());
            System.out.println(tid2pid);
            criticalVMclass vmTmp = pid2VM.get(pid.intValue());
            vmTmp.setVcpu(tid.intValue(), vCPU_ID.intValue());
            vmTmp.setCr3(vCPU_ID.intValue(), cr3);
            pid2VM.put(pid.intValue(),vmTmp);
            // Start of process do something with vertex
        }
        //String hostID = event.getTrace().getHostId();



        String lastCr3 = pid2VM.get(pid.intValue()).getCr3(vCPU_ID.intValue());
        pid2VM.get(pid.intValue()).setCr3(vCPU_ID.intValue(), cr3);
        if (!lastCr3.equals(cr3) && !lastCr3.equals("0") && !lastCr3.equals("1")) {
            // Add vertex that this one wakeup last one
            Integer ftid =  pid2VM.get(pid.intValue()).getFtid(cr3);
            Integer Lastftid =  pid2VM.get(pid.intValue()).getFtid(lastCr3);

            OsWorker wakeup = getOrCreateKernelWorker(pid.intValue(), ftid, ts);
            TmfVertex wakeupVertex = new TmfVertex(ts);
            TmfVertex wakeeVertex = new TmfVertex(ts);

            OsWorker wakee = getOrCreateKernelWorker(pid.intValue(), Lastftid, ts);
            graph.append(wakeup, wakeupVertex, EdgeType.BLOCKED);
            graph.append(wakee, wakeeVertex, EdgeType.RUNNING);
            wakeeVertex.linkVertical(wakeupVertex);
            pid2VM.get(pid.intValue()).setAcceptIrq(cr3,0);
        } else if (lastCr3.equals(cr3)) {
            pid2VM.get(pid.intValue()).setAcceptIrq(cr3,0);
        } else if (lastCr3.equals("0")) {
            pid2VM.get(pid.intValue()).setAcceptIrq(cr3,1);
        } else if (lastCr3.equals("1")) {

            Integer ftid =  pid2VM.get(pid.intValue()).getFtid(cr3);
            OsWorker schedOutWorker = getOrCreateKernelWorker(pid.intValue(), ftid , ts);
            TmfVertex schedOutVertex = new TmfVertex(ts);
            graph.append(schedOutWorker, schedOutVertex, EdgeType.PREEMPTED);
        }


    }
}
