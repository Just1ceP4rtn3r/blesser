package org.blesser.blelearner.ModifiedLStar;

import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealy;
import de.learnlib.algorithms.lstargeneric.ExtensibleAutomatonLStar.BuilderDefaults;
import de.learnlib.algorithms.lstargeneric.ce.ObservationTableCEXHandler;
import de.learnlib.algorithms.lstargeneric.closing.ClosingStrategy;
import de.learnlib.api.MembershipOracle;
import java.util.List;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;

public class ModifiedExtensibleLStarMealyBuilder<I, O> {
    private Alphabet<I> alphabet;
    private MembershipOracle<I, Word<O>> oracle;
    private List<Word<I>> initialPrefixes = BuilderDefaults.initialPrefixes();
    private List<Word<I>> initialSuffixes = BuilderDefaults.initialSuffixes();
    private ObservationTableCEXHandler<? super I, ? super Word<O>> cexHandler = BuilderDefaults.cexHandler();
    private ClosingStrategy<? super I, ? super Word<O>> closingStrategy = BuilderDefaults.closingStrategy();

    public ModifiedExtensibleLStarMealyBuilder() {
    }

}
