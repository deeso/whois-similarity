package whois.similarity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import nmdistance.DomainInfo;
import nmdistance.DomainProcessor;
import nmdistance.Similarity;
import nmdistance.SimilarityResult;

public class Main {
	static boolean initted = false;
	static ArgumentParser parser;
	static Namespace ns = null;
	
	static String DOMAINS = "domains";
	static String SIMILAR = "similar";
	static String FILES = "files";
	static String FILE = "file";
	static String ZIP = "zip";
	static String DOWNLOAD = "download";
	static String SAVE = "save";
	static String ALGORITHM = "algorithm";
	static String CONTAINS = "contains";
	static String CONTAINS_ALGORITHM = "contains_algorithm";
	static String MATCHES = "matches";
	static String THRESHOLD = "threshold";
	static String DOMAIN_CENTRIC = "domain_centric";
	static String STRINGS = "string_centric";
	static String JSON = "json";
	static String ACTION = "action";
	static String[] ACTIONS = {FILE, ZIP, DOWNLOAD};
	// Algorithms

	
	public static void init() {
		if (initted || ns != null)
			return;
	    parser = ArgumentParsers.newFor("whois-similarity").build()
	            .defaultHelp(true)
	            .description("Calculate similarity of domain name to a given string.");
	    
	    parser.addArgument("-"+ACTION).type(String.class)
		.choices(ACTIONS).setDefault(DOWNLOAD)
		.help("specify the matching algorithms to use");
	    
	    parser.addArgument("-"+FILE).nargs("+")
	    		.type(String.class)
	    		.help("process downloaded files");
	    
	    parser.addArgument("-"+ZIP).nargs("+")
			.type(String.class)
			.help("process downloaded zip files");
	    
	    parser.addArgument("-"+DOWNLOAD).action(Arguments.storeTrue())
		.help("domain name centric analysis");
	    
	    parser.addArgument("-"+SAVE).type(String.class)
		  .help("specify the name of the file");

	    parser.addArgument("-"+DOMAINS).nargs("+").type(String.class)
			  .help("specify the domains to compare");
	    parser.addArgument("-"+SIMILAR).nargs("+").type(String.class)
	            .help("specify the string to compare");
	    parser.addArgument("-"+DOMAINS).nargs("+").type(String.class)
	    		.help("specify the domains to compare");
	    parser.addArgument("-"+DOMAIN_CENTRIC).action(Arguments.storeTrue())
		.help("domain name centric analysis");
	    parser.addArgument("-"+ALGORITHM).type(String.class)
	    		.choices(Similarity.VALID_CHOICES).setDefault(Similarity.ALL)
	    		.help("specify the matching algorithms to use");
	    parser.addArgument("-"+CONTAINS).action(Arguments.storeTrue())
				.help("check to see if strings contain value");
	    parser.addArgument("-"+CONTAINS_ALGORITHM).type(String.class)
				.choices(Similarity.VALID_CHOICES).setDefault(Similarity.ALL)
				.help("specify the algorithms to use when detecting string presence (ignored for domain_centric analysis)");
	    parser.addArgument("-"+MATCHES).action(Arguments.storeTrue())
				.help("determine similarity on matches only");
	    parser.addArgument("-"+THRESHOLD).type(Double.class).setDefault(0.0)
				.help("specify the minimum threshold for matches");
	    parser.addArgument("-"+JSON).action(Arguments.storeTrue())
				.help("output json content");
	}
	
	@SuppressWarnings("unchecked")
	public static void performStringCentric() {
		ArrayList<String> domains = new ArrayList<String>();
		for (String s: (ArrayList<String>) ns.get(DOMAINS)) {
			if (s != null && s.length() > 0) {
				domains.add(s);
			}
		}
		ArrayList<String> similars = new ArrayList<String>();
		for (String s: (ArrayList<String>) ns.get(SIMILAR)) {
			if (s != null && s.length() > 0) {
				similars.add(s);
			}
		}
		
		boolean exec_contains = ns.getBoolean(CONTAINS);
		boolean exec_matches = ns.getBoolean(MATCHES);
		double threshold = ns.getDouble(THRESHOLD);
		ArrayList<SimilarityResult> results = new ArrayList<SimilarityResult>();
		HashMap<String, HashMap<String, Boolean>> contains = new HashMap<String, HashMap<String, Boolean>>();
		
		
		if (exec_contains || exec_matches) {
			contains = Similarity.fuzzy_contains(ns.getString(CONTAINS_ALGORITHM), similars, domains, threshold);
		}
		
		if (!exec_contains && !exec_matches)
			results = Similarity.executeByName(ns.getString(ALGORITHM), similars, domains);
		else if (exec_matches)
			results = Similarity.similarityForMatchesOnly(ns.getString(ALGORITHM), contains, threshold);

		if (exec_contains) {
			for (String s: contains.keySet()) {
				HashMap<String, Boolean> dmatches =  contains.get(s);
				for (Map.Entry<String,Boolean> e : dmatches.entrySet()) {
					System.out.println(String.format("%s contains %s ? %s", e.getKey(), s, e.getValue()));
				}
			}
		} else {
			for (SimilarityResult sr: results) {
				if (sr.isValid())
					System.out.println(String.format("%s", sr.toSimpleString()));
			}
			
		}	
	}
	
	@SuppressWarnings("unchecked")
	public static void performDomainCentric() {
		ArrayList<DomainInfo> domain_infos = new ArrayList<DomainInfo>();
		for (String s: (ArrayList<String>) ns.get(DOMAINS)) {
			if (s != null && s.length() > 0) {
				DomainInfo di = DomainProcessor.processFqdn(s);
				domain_infos.add(di);
			}
		}
		ArrayList<String> similars = new ArrayList<String>();
		for (String s: (ArrayList<String>) ns.get(SIMILAR)) {
			if (s != null && s.length() > 0) {
				similars.add(s);
			}
		}
		
		boolean exec_contains = ns.getBoolean(CONTAINS);
		boolean exec_matches = ns.getBoolean(MATCHES);
		double threshold = ns.getDouble(THRESHOLD);
		
		if (exec_contains || exec_matches) {
			for (String similar : similars) {
				for (DomainInfo di: domain_infos) {
					di.compareString(similar, threshold, ns.getString(ALGORITHM));
				}
			}
		} else {
			for (String similar : similars) {
				for (DomainInfo di: domain_infos) {
					di.measureSimilarity(similar, threshold, ns.getString(ALGORITHM));
				}
			}
		}
		for (DomainInfo di: domain_infos) {
			if (di.hasMatchingResults()) {
				for (String sr: di.getMatchingSimpleStrings()) {
					System.out.println(String.format("%s", sr));
				}	
			}
		}	
	}

	
	public static Namespace parseArgs(String[] args) {
		init();
	    try {
	        ns = parser.parseArgs(args);
	        return ns;
	    } catch (ArgumentParserException e) {
	        parser.handleError(e);
	        System.exit(1);
	    }
	    return null;
	    
	}
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws Exception{
		ns = parseArgs(args);
		if (ns.getBoolean(DOMAIN_CENTRIC)) {
			performDomainCentric();
		} else {
			performStringCentric();
		}

		
	}
}
