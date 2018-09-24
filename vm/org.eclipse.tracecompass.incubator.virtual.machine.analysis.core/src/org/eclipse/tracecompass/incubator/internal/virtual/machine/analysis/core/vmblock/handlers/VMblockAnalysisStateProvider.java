package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelTrace;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.model.qemukvm.QemuKvmStrings;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.model.qemukvm.QemuKvmVmModel;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers.VMblockAnalysisEventHandler;
import org.eclipse.tracecompass.tmf.core.statesystem.AbstractTmfStateProvider;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
import org.eclipse.tracecompass.tmf.core.trace.experiment.TmfExperiment;

import com.google.common.collect.ImmutableMap;
public class VMblockAnalysisStateProvider extends AbstractTmfStateProvider   {

    private static final int VERSION = 2;

    private final Map<String, VMblockAnalysisEventHandler> fEventNames;
    private final Map<ITmfTrace, LayoutHandler> fLayouts = new HashMap<>();
    private QemuKvmVmModel fKvmModel;
    private final Map<IKernelAnalysisEventLayout, LayoutHandler> fMap = new HashMap<>();


    private LayoutHandler getForLayout(IKernelAnalysisEventLayout layout, Map<String, VMblockAnalysisEventHandler> builder) {
        LayoutHandler layoutHandler = fMap.get(layout);
        if (layoutHandler == null) {
            layoutHandler = new LayoutHandler(layout);
            fMap.put(layout, layoutHandler);
            addEventNames(builder, layout);
        }
        return layoutHandler;
    }

    private class LayoutHandler {

        protected final IKernelAnalysisEventLayout fLayout;
        protected final VMblockAnalysisEventHandler fKvmEntryHandler;
        //protected final VMblockAnalysisEventHandler fKvmExitHandler;


        public LayoutHandler(IKernelAnalysisEventLayout layout) {
            fLayout = layout;
            fKvmEntryHandler = new KvmEntryHandler(layout, VMblockAnalysisStateProvider.this);
            //fKvmExitHandler = new KvmExitHandler(layout, VMblockAnalysisStateProvider.this);
        }
    }

    public VMblockAnalysisStateProvider(TmfExperiment experiment) {
        super(experiment, "VM Block State Provider"); //$NON-NLS-1$

        Map<String, VMblockAnalysisEventHandler> builder = new HashMap<>();

        for (ITmfTrace trace : TmfTraceManager.getTraceSet(experiment)) {
            if (trace instanceof IKernelTrace) {
                IKernelAnalysisEventLayout layout = ((IKernelTrace) trace).getKernelEventLayout();
                fLayouts.put(trace, getForLayout(layout, builder));
            }
        }
        fEventNames = ImmutableMap.copyOf(builder);
        fKvmModel = new QemuKvmVmModel(experiment);
    }
    private void addEventNames(Map<String, VMblockAnalysisEventHandler> builder, IKernelAnalysisEventLayout layout) {

        // If you are working on pattern recognition of application
        //builder.put(layout.eventSchedSwitch(), new SchedSwitchHandlerPattern(layout, this));
        //builder.put(layout.eventSyscallEntryPrefix(), new SysEntryHandlerPattern(layout, this));
        //builder.put(layout.eventSyscallExitPrefix(), new SysExitHandlerPattern(layout, this));
        // If you are not working on pattern recognition uncomment next line
        builder.put(layout.eventSchedSwitch(), new SchedSwitchHandler(layout, this));

        //Ask Genvieve
        /*
        VMblockAnalysisEventHandler handler = new KvmEntryHandler(layout, this);
        for (String entryEvent : layout.eventsKVMEntry()) {
            builder.put(entryEvent, handler);
        }
        handler = new KvmExitHandler(layout, this);
        for (String entryEvent : layout.eventsKVMExit()) {
            builder.put(entryEvent, handler);
        }
        */
        builder.put("kvm_entry", new KvmEntryHandler(layout, this)); //$NON-NLS-1$
        builder.put("kvm_exit", new KvmExitHandler(layout, this)); //$NON-NLS-1$

        builder.put("kvm_inj_virq", new KvmInjIrqHandler(layout, this)); //$NON-NLS-1$

        builder.put("kvm_apic_accept_irq", new KvmApicAcceptIrqHandler(layout, this)); //$NON-NLS-1$

        builder.put("addons_vcpu_enter_guest", new KvmVcpuEnterGuestHandler(layout, this)); //$NON-NLS-1$
        builder.put("kvm_hypercall", new KvmHyperCallHandler(layout, this)); //$NON-NLS-1$
        builder.put("sched_ttwu", new KvmttwuHandler(layout, this)); //$NON-NLS-1$
        builder.put("syscall_entry_preadv", new KvmEntryReadHandler(layout, this)); //$NON-NLS-1$
        builder.put("syscall_exit_preadv", new KvmExitReadHandler(layout, this)); //$NON-NLS-1$
        builder.put("syscall_entry_pwritev", new KvmEntryWriteHandler(layout, this)); //$NON-NLS-1$
        builder.put("syscall_exit_pwritev", new KvmExitWriteHandler(layout, this)); //$NON-NLS-1$

    }
    @Override
    public TmfExperiment getTrace() {
        ITmfTrace trace = super.getTrace();
        if (trace instanceof TmfExperiment) {
            return (TmfExperiment) trace;
        }
        throw new IllegalStateException("VMBlockStateProvider: The associated trace should be an experiment"); //$NON-NLS-1$
    }

    @Override
    public int getVersion() {
        return VERSION;
    }


    @Override
    public VMblockAnalysisStateProvider getNewInstance() {
        return new VMblockAnalysisStateProvider(getTrace());
    }

    @Override
    protected void eventHandle(@Nullable ITmfEvent event) {
        if (event == null) {
            return;
        }

        Integer cpu = TmfTraceUtils.resolveIntEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
        if (cpu == null) {
            /* We couldn't find any CPU information, ignore this event */
            return;
        }

        //String traceHost = event.getTrace().getHostId();
        LayoutHandler layoutHandler = fLayouts.get(event.getTrace());
        if (layoutHandler == null) {
            return;
        }
        /*
         * Have the hypervisor models handle the event first.
         */
        fKvmModel.handleEvent(event, layoutHandler.fLayout);

        final String eventName = event.getName();
        //final long ts = event.getTimestamp().getValue();

        final ITmfStateSystemBuilder ss = checkNotNull(getStateSystemBuilder());

        VMblockAnalysisEventHandler handler = fEventNames.get(eventName);
        // TODO: maybe put the other handlers also in fEventNames
        if (handler == null) {
            //IKernelAnalysisEventLayout layout = layoutHandler.fLayout;
            if (isKvmEntry(eventName)) {
                handler = layoutHandler.fKvmEntryHandler;
            }
        }
        if (handler != null) {
            handler.handleEvent(ss, event);
        }


    }
    private static boolean isKvmEntry(String eventName) {
        return eventName.equals(QemuKvmStrings.KVM_ENTRY) || eventName.equals(QemuKvmStrings.KVM_X86_ENTRY);
    }

}
