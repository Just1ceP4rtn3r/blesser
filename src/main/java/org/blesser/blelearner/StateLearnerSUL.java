package org.blesser.blelearner;

import de.learnlib.api.SUL;
import de.learnlib.api.SULException;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

import javax.annotation.Nullable;

public interface StateLearnerSUL<I, O> extends SUL<I, O> {
	default Word<O> stepWord(@Nullable Word<I> in) throws SULException {
		WordBuilder<O> wbOutput = new WordBuilder<>(in.length());
		
		for(I sym: in) {
			wbOutput.add(step(sym));
		}
		
		return wbOutput.toWord();
	}
}
