//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.blesser.blelearner.ModifiedLStar;

import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealy;
import de.learnlib.algorithms.lstargeneric.ce.ObservationTableCEXHandler;
import de.learnlib.algorithms.lstargeneric.closing.ClosingStrategy;
import de.learnlib.algorithms.lstargeneric.table.Row;
import de.learnlib.api.MembershipOracle;
import de.learnlib.oracles.DefaultQuery;

import java.util.Collections;
import java.util.List;

import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;

public class ModifiedExtensibleLStarMealy<I, O> extends ExtensibleLStarMealy {

    public ModifiedExtensibleLStarMealy(Alphabet<I> alphabet, MembershipOracle<I, Word<O>> oracle,
            List<Word<I>> initialSuffixes, ObservationTableCEXHandler<? super I, ? super Word<O>> cexHandler,
            ClosingStrategy<? super I, ? super Word<O>> closingStrategy) {
        super(alphabet, oracle, Collections.singletonList(Word.epsilon()), initialSuffixes, cexHandler,
                closingStrategy);
    }

    


}