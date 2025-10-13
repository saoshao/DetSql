package DetSql;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MyCompareLengthDiffThresholdTest {

    @Test
    public void lengthDiffOverThresholdShouldBeZeroSimilarity_Levenshtein() {
        // Prepare two strings with length difference >= 100 and without prefix/suffix containment
        String s1 = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ"; // 40 chars
        String s2 = "xxxx" + "Z".repeat(200) + "yyyy";             // 208 chars (diff >= 168)
        assertTrue(Math.abs(s1.length() - s2.length()) >= 100);

        List<Double> sims = MyCompare.averageLevenshtein(s1, s2, "", "", false);
        assertNotNull(sims);
        assertFalse(sims.isEmpty());
        double min = sims.stream().min(Double::compareTo).orElse(1.0);
        assertEquals(0.0, min, 1e-9, "When length diff >= 100, similarity should be 0.0");
    }
}
