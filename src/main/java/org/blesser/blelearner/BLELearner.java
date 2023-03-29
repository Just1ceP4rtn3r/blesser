package org.blesser.blelearner;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealy;
import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.malerpnueli.MalerPnueliMealy;
import de.learnlib.algorithms.rivestschapire.RivestSchapireMealy;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.EquivalenceOracle;
import de.learnlib.api.LearningAlgorithm;
import de.learnlib.cache.mealy.MealyCacheOracle;
import de.learnlib.counterexamples.AcexLocalSuffixFinder;
import de.learnlib.eqtests.basic.RandomWordsEQOracle;
import de.learnlib.eqtests.basic.WMethodEQOracle;
import de.learnlib.eqtests.basic.WpMethodEQOracle;
import de.learnlib.logging.LearnLogger;
import de.learnlib.oracles.CounterOracle.MealyCounterOracle;
import de.learnlib.oracles.DefaultQuery;
import de.learnlib.oracles.SULOracle;
import de.learnlib.statistics.Counter;
import de.learnlib.statistics.SimpleProfiler;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Random;
import java.util.logging.*;
import net.automatalib.automata.transout.MealyMachine;
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import org.blesser.blelearner.LogOracle.MealyLogOracle;
import org.blesser.blelearner.ModifiedWMethodEQOracle.MealyModifiedWMethodEQOracle;
import org.blesser.blelearner.smp.SMPLearningConfig;
import org.blesser.blelearner.smp.SMPSUL;

public class BLELearner {

  LearningConfig config; // learner configuration
  boolean combine_query = false;
  SimpleAlphabet<String> alphabet; // input alphabet

  // Membership query
  StateLearnerSUL<String, String> sul;
  MealyLogOracle<String, String> logMemOracle; // log class ,customized
  MealyCounterOracle<String, String> statsMemOracle; // calculate real queries that interact with the system, oracle
  // is used to count
  MealyCacheOracle<String, String> cachedMemOracle; // cache membership oracle
  MealyCounterOracle<String, String> statsCachedMemOracle; // calculate the number of memebership query in the cache
  LearningAlgorithm<MealyMachine<?, String, ?, String>, String, Word<String>> learningAlgorithm; // membership query
  // algorithm

  // Equivalence query
  SULOracle<String, String> eqOracle;
  MealyLogOracle<String, String> logEqOracle;
  MealyCounterOracle<String, String> statsEqOracle;
  MealyCacheOracle<String, String> cachedEqOracle;
  MealyCounterOracle<String, String> statsCachedEqOracle;
  EquivalenceOracle<MealyMachine<?, String, ?, String>, String, Word<String>> equivalenceAlgorithm;

  Logger logble = Logger.getLogger("ble.log");
  FileHandler fileHandler;

  public BLELearner(LearningConfig config) throws Exception {
    this.config = config;

    try {
      fileHandler = new FileHandler(config.output_dir + "ble.log");
    } catch (SecurityException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }

    fileHandler.setLevel(Level.INFO);
    fileHandler.setFormatter(
      new Formatter() {
        SimpleDateFormat format = new SimpleDateFormat("YYYY-MM-dd HH:MM:ss S");

        public String format(LogRecord record) {
          return (
            format.format(record.getMillis()) +
            " " +
            record.getSourceClassName() +
            "\n" +
            record.getSourceMethodName() +
            "\n" +
            record.getLevel() +
            ": " +
            " " +
            record.getMessage() +
            "\n"
          );
        }
      }
    );
    logble.addHandler(fileHandler);
    logble.setUseParentHandlers(false);

    // Create output directory if it doesn't exist
    Path path = Paths.get(config.output_dir);
    if (Files.notExists(path)) {
      Files.createDirectories(path);
    }

    configureLogging(config.output_dir);

    LearnLogger log = LearnLogger.getLogger(BLELearner.class.getSimpleName());
    // Check the type of learning we want to do and create corresponding
    // configuration and SUL
    if (config.type == LearningConfig.TYPE_CONTROLLER) {
      log.log(Level.INFO, "Using BLE devices SUL");

      // Create the openflow controller SUL
      sul = new SMPSUL(new SMPLearningConfig(config));
      alphabet = ((SMPSUL) sul).getAlphabet();
    }

    loadLearningAlgorithm(config.learning_algorithm, alphabet, sul);
    loadEquivalenceAlgorithm(config.eqtest, alphabet, sul);
  }

  public void loadLearningAlgorithm(
    String algorithm,
    SimpleAlphabet<String> alphabet,
    StateLearnerSUL<String, String> sul
  ) throws Exception {
    // Create the membership oracle
    // memOracle = new SULOracle<String, String>(sul);
    // Add a logging oracle
    logMemOracle =
      new MealyLogOracle<String, String>(
        sul,
        LearnLogger.getLogger("learning_queries"),
        combine_query
      );
    // Count the number of queries actually sent to the SUL
    statsMemOracle =
      new MealyCounterOracle<String, String>(
        logMemOracle,
        "membership queries to SUL"
      );
    // Use cache oracle to prevent double queries to the SUL
    // cachedMemOracle = MealyCacheOracle.createDAGCacheOracle(alphabet,
    // statsMemOracle);
    // Count the number of queries to the cache
    statsCachedMemOracle =
      new MealyCounterOracle<String, String>(
        statsMemOracle,
        "membership queries to cache"
      );

    // Instantiate the selected learning algorithm
    switch (algorithm.toLowerCase()) {
      case "modified_lstar":
        // TODO: extend the L* algorithm to override the `refineHypothesis` method in class `AbstractLStar`
        // learningAlgorithm = new ModifiedLStarMealyBuilder<String,
        // String>().withAlphabet(alphabet)
        // .withOracle(statsCachedMemOracle).create();
        break;
      case "lstar":
        learningAlgorithm =
          new ExtensibleLStarMealyBuilder<String, String>()
            .withAlphabet(alphabet)
            .withOracle(statsCachedMemOracle)
            .create();
        break;
      case "dhc":
        learningAlgorithm =
          new MealyDHC<String, String>(alphabet, statsCachedMemOracle);
        break;
      case "kv":
        learningAlgorithm =
          new KearnsVaziraniMealy<String, String>(
            alphabet,
            statsCachedMemOracle,
            true,
            AcexAnalyzers.BINARY_SEARCH
          );
        break;
      case "ttt":
        AcexLocalSuffixFinder suffixFinder = new AcexLocalSuffixFinder(
          AcexAnalyzers.BINARY_SEARCH,
          true,
          "Analyzer"
        );
        learningAlgorithm =
          new TTTLearnerMealy<String, String>(
            alphabet,
            statsCachedMemOracle,
            suffixFinder
          );
        break;
      case "mp":
        learningAlgorithm =
          new MalerPnueliMealy<String, String>(alphabet, statsCachedMemOracle);
        break;
      case "rs":
        learningAlgorithm =
          new RivestSchapireMealy<String, String>(
            alphabet,
            statsCachedMemOracle
          );
        break;
      default:
        throw new Exception(
          "Unknown learning algorithm " + config.learning_algorithm
        );
    }
  }

  public void loadEquivalenceAlgorithm(
    String algorithm,
    SimpleAlphabet<String> alphabet,
    StateLearnerSUL<String, String> sul
  ) throws Exception {
    // We could combine the two cached oracle to save some queries to the SUL
    // Create the equivalence oracle
    // eqOracle = new SULOracle<String, String>(sul);
    // Add a logging oracle
    logEqOracle =
      new MealyLogOracle<String, String>(
        sul,
        LearnLogger.getLogger("equivalence_queries"),
        combine_query
      );
    // Add an oracle that counts the number of queries
    statsEqOracle =
      new MealyCounterOracle<String, String>(
        logEqOracle,
        "equivalence queries to SUL"
      );
    // Use cache oracle to prevent double queries to the SUL
    // cachedEqOracle = MealyCacheOracle.createDAGCacheOracle(alphabet,
    // statsEqOracle);
    // Count the number of queries to the cache
    statsCachedEqOracle =
      new MealyCounterOracle<String, String>(
        statsEqOracle,
        "equivalence queries to cache"
      );

    // Instantiate the selected equivalence algorithm
    switch (algorithm.toLowerCase()) {
      case "wmethod":
        equivalenceAlgorithm =
          new WMethodEQOracle.MealyWMethodEQOracle<String, String>(
            config.max_depth,
            statsCachedEqOracle
          );
        break;
      case "modifiedwmethod":
        equivalenceAlgorithm =
          new MealyModifiedWMethodEQOracle<String, String>(
            config.max_depth,
            statsCachedEqOracle
          );
        break;
      case "wpmethod":
        equivalenceAlgorithm =
          new WpMethodEQOracle.MealyWpMethodEQOracle<String, String>(
            config.max_depth,
            statsCachedEqOracle
          );
        break;
      case "randomwords":
        equivalenceAlgorithm =
          new RandomWordsEQOracle.MealyRandomWordsEQOracle<String, String>(
            statsCachedEqOracle,
            config.min_length,
            config.max_length,
            config.nr_queries,
            new Random(config.seed)
          );
        break;
      default:
        throw new Exception("Unknown equivalence algorithm " + config.eqtest);
    }
  }

  public void learn() throws IOException, InterruptedException {
    LearnLogger log = LearnLogger.getLogger(BLELearner.class.getSimpleName());
    log.log(
      Level.INFO,
      "Using learning algorithm " + learningAlgorithm.getClass().getSimpleName()
    );
    log.log(
      Level.INFO,
      "Using equivalence algorithm " +
      equivalenceAlgorithm.getClass().getSimpleName()
    );

    log.log(Level.INFO, "Starting learning");

    SimpleProfiler.start("Total time");

    boolean learning = true;
    Counter round = new Counter("Rounds", "");

    round.increment();
    log.logPhase("Starting round " + round.getCount());
    SimpleProfiler.start("Learning");
    learningAlgorithm.startLearning();
    SimpleProfiler.stop("Learning");

    MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();

    while (learning) {
      // Write outputs
      writeDotModel(
        hypothesis,
        alphabet,
        config.output_dir + "/hypothesis_" + round.getCount() + ".dot"
      );

      // Search counter-example
      SimpleProfiler.start("Searching for counter-example");
      DefaultQuery<String, Word<String>> counterExample = equivalenceAlgorithm.findCounterExample(
        hypothesis,
        alphabet
      );
      SimpleProfiler.stop("Searching for counter-example");

      if (counterExample == null) {
        // No counter-example found, so done learning
        learning = false;

        // Write outputs
        writeDotModel(
          hypothesis,
          alphabet,
          config.output_dir + "/learnedModel.dot"
        );
        // writeAutModel(hypothesis, alphabet, config.output_dir + "/learnedModel.aut");
      } else {
        // Counter example found, update hypothesis and continue learning
        log.logCounterexample(
          "Counter-example found: " + counterExample.toString()
        );
        // Add more logging
        round.increment();
        log.logPhase("Starting round " + round.getCount());

        // TODO: Overriding the refinement method to refine the hypothesis in any case
        // (We just need one round of membership queries)
        SimpleProfiler.start("Learning");
        learningAlgorithm.refineHypothesis(counterExample);
        SimpleProfiler.stop("Learning");

        hypothesis = learningAlgorithm.getHypothesisModel();
      }
    }

    SimpleProfiler.stop("Total time");

    // Output statistics
    log.log(
      Level.INFO,
      "-------------------------------------------------------"
    );
    log.log(Level.INFO, SimpleProfiler.getResults());
    log.log(Level.INFO, round.getSummary());
    log.log(Level.INFO, statsMemOracle.getStatisticalData().getSummary());
    log.log(Level.INFO, statsCachedMemOracle.getStatisticalData().getSummary());
    log.log(Level.INFO, statsEqOracle.getStatisticalData().getSummary());
    log.log(Level.INFO, statsCachedEqOracle.getStatisticalData().getSummary());
    log.log(Level.INFO, "States in final hypothesis: " + hypothesis.size());
  }

  public static void writeDotModel(
    MealyMachine<?, String, ?, String> model,
    SimpleAlphabet<String> alphabet,
    String filename
  ) throws IOException, InterruptedException {
    // Write output to dot-file
    File dotFile = new File(filename);
    PrintStream psDotFile = new PrintStream(dotFile);
    GraphDOT.write(model, alphabet, psDotFile);
    psDotFile.close();

    // Check if dot is available

    // Convert .dot to .pdf
    Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
  }

  public void configureLogging(String output_dir)
    throws SecurityException, IOException {
    LearnLogger loggerLearnlib = LearnLogger.getLogger("de.learnlib");
    loggerLearnlib.setLevel(Level.ALL);
    FileHandler fhLearnlibLog = new FileHandler(output_dir + "/learnlib.log");
    loggerLearnlib.addHandler(fhLearnlibLog);
    fhLearnlibLog.setFormatter(new SimpleFormatter());

    LearnLogger loggerLearner = LearnLogger.getLogger(
      BLELearner.class.getSimpleName()
    );
    loggerLearner.setLevel(Level.ALL);
    FileHandler fhLearnerLog = new FileHandler(output_dir + "/learner.log");
    loggerLearner.addHandler(fhLearnerLog);
    fhLearnerLog.setFormatter(new SimpleFormatter());
    loggerLearner.addHandler(new ConsoleHandler());

    LearnLogger loggerLearningQueries = LearnLogger.getLogger(
      "learning_queries"
    );
    loggerLearningQueries.setLevel(Level.ALL);
    FileHandler fhLearningQueriesLog = new FileHandler(
      output_dir + "/learning_queries.log"
    );
    loggerLearningQueries.addHandler(fhLearningQueriesLog);
    fhLearningQueriesLog.setFormatter(new SimpleFormatter());
    loggerLearningQueries.addHandler(new ConsoleHandler());

    LearnLogger loggerEquivalenceQueries = LearnLogger.getLogger(
      "equivalence_queries"
    );
    loggerEquivalenceQueries.setLevel(Level.ALL);
    FileHandler fhEquivalenceQueriesLog = new FileHandler(
      output_dir + "/equivalence_queries.log"
    );
    loggerEquivalenceQueries.addHandler(fhEquivalenceQueriesLog);
    fhEquivalenceQueriesLog.setFormatter(new SimpleFormatter());
    loggerEquivalenceQueries.addHandler(new ConsoleHandler());
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Invalid number of parameters");
      System.exit(-1);
    }

    LearningConfig config = new LearningConfig(args[0]);

    BLELearner learner = new BLELearner(config);
    learner.learn();
  }
}
