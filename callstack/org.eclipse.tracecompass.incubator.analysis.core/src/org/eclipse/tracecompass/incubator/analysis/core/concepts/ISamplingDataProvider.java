/*******************************************************************************
 * Copyright (c) 2017 École Polytechnique de Montréal
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/

package org.eclipse.tracecompass.incubator.analysis.core.concepts;

import java.util.Collection;

/**
 * Interfaces that classes providing sampling data for threads can implement
 *
 * @author Geneviève Bastien
 */
public interface ISamplingDataProvider {

    /**
     * Get the aggregated sample data for a thread in a time range.
     *
     * @param tid
     *            The ID of the thread
     * @param start
     *            The start of the period for which to get the time on CPU
     * @param end
     *            The end of the period for which to get the time on CPU
     * @return The collection of aggregated sampling data for the time range
     */
    Collection<AggregatedCallSite> getSamplingData(int tid, long start, long end);

}
