package cz.muni.fi.keycheck;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author David Formanek
 */
class StatsContainer implements Stats {
    private List<Stats> statsInstances = new ArrayList<>();
    
    public void add(Stats stats) {
        statsInstances.add(stats);
    }

    @Override
    public void process(Params params) {
        for (Stats statsInstance : statsInstances) {
            statsInstance.process(params);
        }
    }

    @Override
    public void print() {
        for (Stats statsInstance : statsInstances) {
            statsInstance.print();
        }
    }
}
