/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2017 Fabian Prasser, Florian Kohlmayer and contributors
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.deidentifier.arx.criteria;

import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.FastIntDoubleMap;
import org.deidentifier.arx.certificate.elements.ElementData;
import org.deidentifier.arx.examples.SpeedTestTCloseness;
import org.deidentifier.arx.framework.check.groupify.HashGroupifyEntry;
import org.deidentifier.arx.framework.data.DataManager;
import org.deidentifier.arx.framework.lattice.Transformation;

import com.carrotsearch.hppc.IntDoubleOpenHashMap;

/**
 * The t-closeness criterion for ordered attributes.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class OrderedDistanceTClosenessFastHashMap extends TCloseness {

	/** SVUID */
	private static final long serialVersionUID = -2395544663063577862L;

	/** The original distribution. */
	private double[] distribution;

	/** The order of the elements. */
	private int[] order;

	public boolean MEASURE_TOTAL_TIME = false;
	public boolean MEASURE_BLOCKS = false;
	public boolean COUNT_ABORTS = false;
	public long TOTAL_CALLS = 0l;
	public long ABORTS = 0l;
	public long TIME_BLOCK_1 = 0l;
	public long TIME_BLOCK_2 = 0l;
	public long TOTAL_TIME = 0l;

	private long time_overall = 0l;
	private long time_blocks = 0l;

	/**
	 * Creates a new instance of the t-closeness criterion for ordered
	 * attributes as proposed in: Li N, Li T, Venkatasubramanian S. t-Closeness:
	 * Privacy beyond k-anonymity and l-diversity. 23rd International Conference
	 * on Data Engineering. 2007:106-115.
	 *
	 * @param attribute
	 * @param t
	 */
	public OrderedDistanceTClosenessFastHashMap(String attribute, double t) {
		super(attribute, t);
	}

	@Override
	public OrderedDistanceTClosenessFastHashMap clone() {
		return new OrderedDistanceTClosenessFastHashMap(this.getAttribute(), this.getT());
	}

	@Override
	public void initialize(DataManager manager, ARXConfiguration config) {
		super.initialize(manager, config);
		this.distribution = manager.getDistribution(attribute);
		this.order = manager.getOrder(attribute);
	}

	@Override
	public boolean isAnonymous(Transformation node, HashGroupifyEntry entry) {

		if (COUNT_ABORTS || MEASURE_BLOCKS || MEASURE_TOTAL_TIME)
			TOTAL_CALLS++;

		if (MEASURE_TOTAL_TIME)
			time_overall = System.nanoTime();
		if (MEASURE_BLOCKS)
			time_blocks = System.nanoTime();

		// Init
		int[] buckets = entry.distributions[index].getBuckets();
		double count = entry.count;

		// Prepare
		FastIntDoubleMap map = new FastIntDoubleMap(buckets.length / 2);
		for (int i = 0; i < buckets.length; i += 2) {
			if (buckets[i] != -1) { // bucket not empty
				int value = buckets[i];
				double frequency = ((double) buckets[i + 1] / count);
				map.put(value, frequency);
			}
		}

		double threshold = t * (order.length - 1d);
		double distance = 0d;
		double sum_i = 0d;

		if (MEASURE_BLOCKS) {
			TIME_BLOCK_1 += System.nanoTime() - time_blocks;
			time_blocks = System.nanoTime();
		}

		// Calculate and check
		for (int i = 0; i < order.length; i++) {
			
			// Compute summands and distance
			int value = order[i];
			sum_i += (map.get(value, 0d) - distribution[value]);
			distance += Math.abs(sum_i);

			// Early abort
			if (distance > threshold) {
				if (MEASURE_BLOCKS)
					TIME_BLOCK_2 += System.nanoTime() - time_blocks;
				if (MEASURE_TOTAL_TIME)
					TOTAL_TIME += System.nanoTime() - time_overall;
				return false;
			}
		}

		// Yes
		if (MEASURE_BLOCKS)
			TIME_BLOCK_2 += System.nanoTime() - time_blocks;
		if (MEASURE_TOTAL_TIME)
			TOTAL_TIME += System.nanoTime() - time_overall;
		return true;
	}

	@Override
	public boolean isLocalRecodingSupported() {
		return true;
	}

	@Override
	public ElementData render() {
		ElementData result = new ElementData("t-Closeness");
		result.addProperty("Attribute", attribute);
		result.addProperty("Threshold (t)", this.t);
		result.addProperty("Distance", "Ordered");
		return result;
	}

	@Override
	public String toString() {
		return t + "-closeness with ordered distance for attribute '" + attribute + "'";
	}
}
