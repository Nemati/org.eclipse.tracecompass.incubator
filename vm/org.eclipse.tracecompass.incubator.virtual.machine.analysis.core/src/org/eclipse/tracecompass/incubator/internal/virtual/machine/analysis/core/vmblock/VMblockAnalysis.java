package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock;

import static org.eclipse.tracecompass.common.core.NonNullUtils.checkNotNull;

import java.util.Collections;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.tracecompass.common.core.NonNullUtils;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.virtual.resources.Messages;
import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers.VMblockAnalysisStateProvider;
import org.eclipse.tracecompass.tmf.core.analysis.requirements.TmfAbstractAnalysisRequirement;
import org.eclipse.tracecompass.tmf.core.statesystem.ITmfStateProvider;
import org.eclipse.tracecompass.tmf.core.statesystem.TmfStateSystemAnalysisModule;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.experiment.TmfExperiment;

/**
 * @author Hani Nemati
 *
 */
public class VMblockAnalysis extends TmfStateSystemAnalysisModule {
    /** The ID of this analysis module */
    public static final String ID = "org.eclipse.tracecompass.incubator.virtual.machine.analysis.VMblockAnalysis"; //$NON-NLS-1$

    private static final Set<TmfAbstractAnalysisRequirement> REQUIREMENTS;

    static {
        REQUIREMENTS = checkNotNull(Collections.EMPTY_SET);
    }
    @Override
    protected @NonNull ITmfStateProvider createStateProvider() {
        ITmfTrace trace = getTrace();
        if (!(trace instanceof TmfExperiment)) {
            throw new IllegalStateException();
        }

        return new VMblockAnalysisStateProvider((TmfExperiment) trace);
    }
    @Override
    protected String getFullHelpText() {
        return NonNullUtils.nullToEmptyString(Messages.blockanaltsisVirtualMachineAnalysis_Help);
    }

    @SuppressWarnings("null")
    @Override
    public Iterable<TmfAbstractAnalysisRequirement> getAnalysisRequirements() {
        return REQUIREMENTS;
    }
}
