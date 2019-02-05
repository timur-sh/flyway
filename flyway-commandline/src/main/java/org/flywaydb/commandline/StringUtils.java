package org.flywaydb.commandline;

public class StringUtils {
    public static String joinStringsBySlash(String part1, String part2) {
        String result = "";
        
        if (part1.endsWith("/")) {
            result = part1;
        } else {
            result = part1 + "/";
        }
    
        if (part2.startsWith("/")) {
            part2 = part1.substring(1);
        }
        
        result += part2;
    
        return result;
    }
    
}
