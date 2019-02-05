package org.flywaydb.commandline;

import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.internal.util.ClassUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class BaseConfUtil {
    private static final String PATCH_SCHEMA_SUFFIX = "_patch";
    private static final String INSTALL_SCHEMA_SUFFIX = "_install";
    
    public static final String BASE_CONF = "base.conf";
    public static final String DIR_PREFIX = "dir.";
    public static final String CONFIG_PREFIX = "config.";
    public static final String TABLE_BASE_PREFIX = "table-base.";
    public static final String PATCH_DIR = "dir-patch";
    public static final String CREATE_TABLE_DIR = "create-scripts";
    public static final String ALTER_TABLE_DIR = "alter-scripts";
    public static final String POPULATE_TABLE_DIR = "populate-scripts";
    public static final String UPDATE_TABLE_DIR = "update-scripts";
    public static final String OTHER_TABLE_DIR = "other-scripts";
    
    
    public static String buildLocations(Properties properties, String module, boolean isPatch) {
        if (!properties.containsKey(DIR_PREFIX + module)) {
            throw new FlywayException(DIR_PREFIX + module + " param not found in " + BASE_CONF);
        }
        // installation dir
        String baseDir = properties.getProperty(DIR_PREFIX + module);
    
        if (isPatch) {
            String version = properties.getProperty("version");
            baseDir += StringUtils.joinStringsBySlash(baseDir, properties.getProperty(PATCH_DIR));
            baseDir += StringUtils.joinStringsBySlash(baseDir, properties.getProperty(version));
        }
    
    
        List<String> dirs = new ArrayList<>();
    
        if (properties.containsKey(CREATE_TABLE_DIR)) {
            dirs.add(StringUtils.joinStringsBySlash(baseDir, properties.getProperty(CREATE_TABLE_DIR)));
        }
    
        if (properties.containsKey(ALTER_TABLE_DIR)) {
            dirs.add(StringUtils.joinStringsBySlash(baseDir, properties.getProperty(ALTER_TABLE_DIR)));
        }
    
        if (properties.containsKey(POPULATE_TABLE_DIR)) {
            dirs.add(StringUtils.joinStringsBySlash(baseDir, properties.getProperty(POPULATE_TABLE_DIR)));
        }
        
        if (properties.containsKey(UPDATE_TABLE_DIR)) {
            dirs.add(StringUtils.joinStringsBySlash(baseDir, properties.getProperty(UPDATE_TABLE_DIR)));
        }
    
        if (properties.containsKey(OTHER_TABLE_DIR)) {
            String[] otherTableDirs = properties.getProperty(OTHER_TABLE_DIR).split(",");
    
            for (String dir : otherTableDirs) {
                dirs.add(StringUtils.joinStringsBySlash(baseDir, dir));
            }
        }
    
        return String.join(",", dirs);
    }
    
    
    public static String buildSchemaTable(Properties properties, String module, boolean isPatch) {
        if (!properties.containsKey(TABLE_BASE_PREFIX + module)) {
            throw new FlywayException("Property '" + TABLE_BASE_PREFIX + module + "' not specified in " + BASE_CONF);
        }
    
        String baseSchemaName = properties.getProperty(TABLE_BASE_PREFIX + module);
    
        baseSchemaName += isPatch
            ? PATCH_SCHEMA_SUFFIX
            : INSTALL_SCHEMA_SUFFIX;
    
        return baseSchemaName;
    }
    
    
    /**
     * @return The installation directory of the Flyway Command-line tool.
     */
    @SuppressWarnings("ConstantConditions")
    public static String getInstallationDir() {
        String path = ClassUtils.getLocationOnDisk(BaseConfUtil.class);
        return new File(path) // jar file
            .getParentFile() // edition dir
            .getParentFile() // lib dir
            .getParentFile() // installation dir
            .getAbsolutePath();
    }
    
}
