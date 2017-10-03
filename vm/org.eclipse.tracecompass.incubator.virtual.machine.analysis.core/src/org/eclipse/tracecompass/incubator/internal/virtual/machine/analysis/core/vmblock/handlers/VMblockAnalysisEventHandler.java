package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;
import org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelAnalysisEventLayout;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers.VMblockAnalysisStateProvider;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;


/**
 * @author Hani Nemati
 *
 */
public abstract class VMblockAnalysisEventHandler {

    private final IKernelAnalysisEventLayout vLayout;
    private VMblockAnalysisStateProvider vStateProvider;
    /**
     * @param layout
     * @param sp
     */
    public VMblockAnalysisEventHandler(IKernelAnalysisEventLayout layout, VMblockAnalysisStateProvider sp) {
        vLayout = layout;
        vStateProvider = sp;
    }
    /**
     * @return
     */
    public VMblockAnalysisStateProvider getStateProvider() {
        return vStateProvider;
    }

/**
 * @return
 */
protected IKernelAnalysisEventLayout getLayout() {
    return vLayout;
}

/**
 * @param ss
 * @param event
 */
public abstract void handleEvent(ITmfStateSystemBuilder ss, ITmfEvent event);


}