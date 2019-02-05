/*
 * Copyright 2010-2018 Boxfuse GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flywaydb.commandline;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationInfoService;
import org.flywaydb.core.api.MigrationVersion;
import org.flywaydb.core.api.logging.Log;
import org.flywaydb.core.api.logging.LogFactory;
import org.flywaydb.core.internal.configuration.ConfigUtils;
import org.flywaydb.core.internal.info.MigrationInfoDumper;
import org.flywaydb.core.internal.util.ClassUtils;
import org.flywaydb.core.internal.util.StringUtils;
import org.flywaydb.core.internal.license.VersionPrinter;
import org.flywaydb.core.internal.logging.console.ConsoleLog.Level;
import org.flywaydb.core.internal.logging.console.ConsoleLogCreator;

import java.io.Console;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.flywaydb.commandline.BaseConfUtil.getInstallationDir;

/**
 * Main class and central entry point of the Flyway command-line tool.
 */
public class Main {
    private static Log LOG;

    private static List<String> VALID_OPERATIONS_AND_FLAGS = Arrays.asList("-X", "-q", "-n", "-v", "-?",
            "-community", "-pro", "-enterprise", "-install", "-patch", //"-module", "-version",
            "help", "migrate", "clean", "info", "validate", "undo", "baseline", "repair");

    private static List<String> NON_FLYWAY_ARGS = Arrays.asList("install", "patch", "module", "version");

    /**
     * Initializes the logging.
     *
     * @param level The minimum level to log at.
     */
    static void initLogging(Level level) {
        LogFactory.setFallbackLogCreator(new ConsoleLogCreator(level));
        LOG = LogFactory.getLog(Main.class);
    }

    /**
     * Main method.
     *
     * @param args The command-line arguments.
     */
    public static void main(String[] args) {
        Level logLevel = getLogLevel(args);
        initLogging(logLevel);

        try {
            if (isPrintVersionAndExit(args)) {
                printVersion();
                System.exit(0);
            }

            List<String> operations = determineOperations(args);
            if (operations.isEmpty() || operations.contains("help") || isFlagSet(args, "-?")) {
                printUsage();
                return;
            }

            validateArgs(args);

            Map<String, String> envVars = ConfigUtils.environmentVariablesToPropertyMap();

            Properties flywayProperties = new Properties();
            initializeDefaults(flywayProperties);
            
            // populate properties from args
            overrideConfigurationWithArgs(flywayProperties, args);
            validateProperties(flywayProperties, args, operations);
            
            loadConfigurationFromConfigFiles(flywayProperties, args, envVars);
            flywayProperties.putAll(envVars);

            // override loaded properties from file by args
            overrideConfigurationWithArgs(flywayProperties, args);

            if (!isSuppressPrompt(args)) {
                promptForCredentialsIfMissing(flywayProperties);
            }

            dumpConfiguration(flywayProperties);

            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            classLoader = loadJdbcDrivers(classLoader);
            classLoader = loadJavaMigrationsFromJarDirs(classLoader, flywayProperties);

            filterProperties(flywayProperties);
            Flyway flyway = Flyway.configure(classLoader).configuration(flywayProperties).load();

            for (String operation : operations) {
                executeOperation(flyway, operation);
            }
        } catch (Exception e) {
            if (logLevel == Level.DEBUG) {
                LOG.error("Unexpected error", e);
            } else {
                if (e instanceof FlywayException) {
                    LOG.error(e.getMessage());
                } else {
                    LOG.error(e.toString());
                }
            }
            System.exit(1);
        }
    }

    static void validateArgs(String[] args) {
        for (String arg : args) {
            if (!isPropertyArgument(arg) && !VALID_OPERATIONS_AND_FLAGS.contains(arg)) {
                throw new FlywayException("Invalid argument: " + arg);
            }
        }
    }
    
    /**
     * @param properties
     * @param args
     * @param operations
     */
    static void validateProperties(Properties properties, String[] args, List<String> operations) {
        if (!properties.containsKey("module")) {
            throw new FlywayException("Options 'module' must be specified");
        }
        
        boolean containsVersion = properties.containsKey("version");
        if ((!isPatch(args) && !isInstall(args)) || (isPatch(args) && isInstall(args))) {
            throw new FlywayException("Either flag '-install' or '-patch' must be specified");
        }
        
        if (isPatch(args) && !containsVersion) {
            throw new FlywayException("Options 'version' must be specified for patch");
        }
    }

    private static boolean isPrintVersionAndExit(String[] args) {
        return isFlagSet(args, "-v");
    }

    private static boolean isSuppressPrompt(String[] args) {
        return isFlagSet(args, "-n");
    }
    
    private static boolean isInstall(String[] args) {
        return isFlagSet(args, "-install");
    }

    private static boolean isPatch(String[] args) {
        return isFlagSet(args, "-patch");
    }

    private static boolean isFlagSet(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Executes this operation on this Flyway instance.
     *
     * @param flyway    The Flyway instance.
     * @param operation The operation to execute.
     */
    private static void executeOperation(Flyway flyway, String operation) {
        if ("clean".equals(operation)) {
            flyway.clean();
        } else if ("baseline".equals(operation)) {
            flyway.baseline();
        } else if ("migrate".equals(operation)) {
            flyway.migrate();
        } else if ("undo".equals(operation)) {
            flyway.undo();
        } else if ("validate".equals(operation)) {
            flyway.validate();
        } else if ("info".equals(operation)) {
            MigrationInfoService info = flyway.info();
            MigrationInfo current = info.current();
            MigrationVersion currentSchemaVersion = current == null ? MigrationVersion.EMPTY : current.getVersion();
            LOG.info("Schema version: " + currentSchemaVersion);
            LOG.info("");
            LOG.info(MigrationInfoDumper.dumpToAsciiTable(info.all()));
        } else if ("repair".equals(operation)) {
            flyway.repair();
        } else {
            LOG.error("Invalid operation: " + operation);
            printUsage();
            System.exit(1);
        }
    }

    /**
     * Checks the desired log level.
     *
     * @param args The command-line arguments.
     * @return The desired log level.
     */
    private static Level getLogLevel(String[] args) {
        for (String arg : args) {
            if ("-X".equals(arg)) {
                return Level.DEBUG;
            }
            if ("-q".equals(arg)) {
                return Level.WARN;
            }
        }
        return Level.INFO;
    }

    /**
     * Initializes the properties with the default configuration for the command-line tool.
     *
     * @param properties The properties object to initialize.
     */
    private static void initializeDefaults(Properties properties) {
        properties.put(ConfigUtils.LOCATIONS, "filesystem:" + new File(getInstallationDir(), "sql").getAbsolutePath());
        properties.put(ConfigUtils.JAR_DIRS, new File(getInstallationDir(), "jars").getAbsolutePath());
    }

    /**
     * Filters there properties to remove the Flyway Commandline-specific ones.
     *
     * @param properties The properties to filter.
     */
    private static void filterProperties(Properties properties) {
        properties.remove(ConfigUtils.JAR_DIRS);
        properties.remove(ConfigUtils.CONFIG_FILES);
        properties.remove(ConfigUtils.CONFIG_FILE_ENCODING);
    
        for (String nonFlywayArg : NON_FLYWAY_ARGS) {
            properties.remove(nonFlywayArg);
        }
    }

    /**
     * Prints the version number on the console.
     */
    private static void printVersion() {
        VersionPrinter.printVersionOnly();
        LOG.info("");

        LOG.debug("Java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");
        LOG.debug(System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch") + "\n");
    }

    /**
     * Prints the usage instructions on the console.
     */
    private static void printUsage() {
        LOG.info("Usage");
        LOG.info("=====");
        LOG.info("");
        LOG.info("flyway [options] command");
        LOG.info("");
        LOG.info("By default, the configuration will be read from conf/flyway.conf.");
        LOG.info("Options passed from the command-line override the configuration.");
        LOG.info("");
        LOG.info("Commands");
        LOG.info("--------");
        LOG.info("migrate  : Migrates the database");
        LOG.info("clean    : Drops all objects in the configured schemas, needs to specify -version option");
        LOG.info("info     : Prints the information about applied, current and pending migrations");
        LOG.info("validate : Validates the applied migrations against the ones on the classpath");
//        LOG.info("undo     : [" + "pro] Undoes the most recently applied versioned migration");
        LOG.info("baseline : Baselines an existing database at the baselineVersion");
        LOG.info("repair   : Repairs the schema history table");
        LOG.info("");
        LOG.info("Options (Format: -key=value)");
        LOG.info("-------");
        LOG.info("module                       : Module alias");
        LOG.info("version                      : Fully qualified version of patch (using with 'clean' and '-patch");
        LOG.info("");
        LOG.info("Flags");
        LOG.info("-----");
        LOG.info("-install    : Run installation SQL scripts");
        LOG.info("-patch      : Run patch. It's necessary to specify -version=<version> option too");
        LOG.info("-X          : Print debug output");
        LOG.info("-q          : Suppress all output, except for errors and warnings");
        LOG.info("-n          : Suppress prompting for a user and password");
        LOG.info("-v          : Print the Flyway version and exit");
        LOG.info("-?          : Print this usage info and exit");
        LOG.info("");
        LOG.info("Example");
        LOG.info("-------");
        LOG.info("flyway -module=mymodule -patch -version=2 migrate");
        LOG.info("flyway -module=mymodule -version=2 clean");
        LOG.info("flyway -module=mymodule -install ");
        LOG.info("");
        LOG.info("More info at https://flywaydb.org/documentation/commandline");
    }

    /**
     * Loads all the driver jars contained in the drivers folder. (For Jdbc drivers)
     *
     * @param classLoader The current ClassLoader.
     * @return The new ClassLoader containing the additional driver jars.
     * @throws IOException When the jars could not be loaded.
     */
    private static ClassLoader loadJdbcDrivers(ClassLoader classLoader) throws IOException {
        File driversDir = new File(getInstallationDir(), "drivers");
        File[] files = driversDir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.endsWith(".jar");
            }
        });

        // see javadoc of listFiles(): null if given path is not a real directory
        if (files == null) {
            LOG.debug("Directory for Jdbc Drivers not found: " + driversDir.getAbsolutePath());
            return classLoader;
        }

        for (File file : files) {
            classLoader = ClassUtils.addJarOrDirectoryToClasspath(classLoader, file.getPath());
        }

        return classLoader;
    }

    /**
     * Loads all the jars contained in the jars folder. (For Java Migrations)
     *
     * @param classLoader The current ClassLoader.
     * @param properties  The configured properties.
     * @return The new ClassLoader containing the additional jars.
     * @throws IOException When the jars could not be loaded.
     */
    private static ClassLoader loadJavaMigrationsFromJarDirs(ClassLoader classLoader, Properties properties) throws IOException {
        String jarDirs = properties.getProperty(ConfigUtils.JAR_DIRS);
        if (!StringUtils.hasLength(jarDirs)) {
            return classLoader;
        }

        jarDirs = jarDirs.replace(File.pathSeparator, ",");
        String[] dirs = StringUtils.tokenizeToStringArray(jarDirs, ",");

        for (String dirName : dirs) {
            File dir = new File(dirName);
            File[] files = dir.listFiles(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return name.endsWith(".jar");
                }
            });

            // see javadoc of listFiles(): null if given path is not a real directory
            if (files == null) {
                LOG.error("Directory for Java Migrations not found: " + dirName);
                System.exit(1);
            }

            for (File file : files) {
                classLoader = ClassUtils.addJarOrDirectoryToClasspath(classLoader, file.getPath());
            }
        }

        return classLoader;
    }

    /**
     * Loads the configuration from the various possible locations.
     *
     * @param flywayProperties The properties object to load to configuration into.
     * @param args       The command-line arguments passed in.
     * @param envVars    The environment variables, converted into properties.
     */
    /* private -> for testing */
    static void loadConfigurationFromConfigFiles(Properties flywayProperties, String[] args, Map<String, String> envVars) {
        String encoding = determineConfigurationFileEncoding(args, envVars);
        String module = flywayProperties.getProperty("module");
        
        // load project properties
        Properties projectProperties = new Properties();
        projectProperties.putAll(ConfigUtils.loadConfigurationFile(new File(getInstallationDir() + "/conf/" + BaseConfUtil.BASE_CONF), encoding, true));
    
        if (projectProperties.isEmpty()) {
            throw new FlywayException("base.conf not found");
        }
        
        if (!projectProperties.containsKey(BaseConfUtil.CONFIG_PREFIX + module)) {
            throw new FlywayException("Configuration file '" + BaseConfUtil.CONFIG_PREFIX + module + "' not found in base.conf");
        }
    
        // load flyway properties
        String flywayConfigFile = projectProperties.getProperty(BaseConfUtil.CONFIG_PREFIX + module);
        flywayProperties.putAll(ConfigUtils.loadConfigurationFile(new File(getInstallationDir() + "/conf/" + flywayConfigFile), encoding, true));

        String locations = BaseConfUtil.buildLocations(projectProperties, module, isPatch(args));
        flywayProperties.put(ConfigUtils.LOCATIONS, locations);
        flywayProperties.put(ConfigUtils.TABLE, BaseConfUtil.buildSchemaTable(projectProperties, module, isPatch(args)));
        
        for (File configFile : determineConfigFilesFromArgs(args, envVars)) {
            flywayProperties.putAll(ConfigUtils.loadConfigurationFile(configFile, encoding, true));
        }
    }

    /**
     * If no user or password has been provided, prompt for it. If you want to avoid the prompt,
     * pass in an empty user or password.
     *
     * @param properties The properties object to load to configuration into.
     */
    private static void promptForCredentialsIfMissing(Properties properties) {
        Console console = System.console();
        if (console == null) {
            // We are running in an automated build. Prompting is not possible.
            return;
        }

        if (!properties.containsKey(ConfigUtils.URL)) {
            // URL is not set. We are doomed for failure anyway.
            return;
        }

        if (!properties.containsKey(ConfigUtils.USER)) {
            properties.put(ConfigUtils.USER, console.readLine("Database user: "));
        }

        if (!properties.containsKey(ConfigUtils.PASSWORD)) {
            char[] password = console.readPassword("Database password: ");
            properties.put(ConfigUtils.PASSWORD, password == null ? "" : String.valueOf(password));
        }
    }

    /**
     * Dumps the configuration to the console when debug output is activated.
     *
     * @param properties The configured properties.
     */
    private static void dumpConfiguration(Properties properties) {
        LOG.debug("Using configuration:");
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            String value = entry.getValue().toString();
            value = ConfigUtils.PASSWORD.equals(entry.getKey()) ? StringUtils.trimOrPad("", value.length(), '*') : value;
            LOG.debug(entry.getKey() + " -> " + value);
        }
    }

    /**
     * Determines the files to use for loading the configuration.
     *
     * @param args    The command-line arguments passed in.
     * @param envVars The environment variables converted to Flyway properties.
     * @return The configuration files.
     */
    private static List<File> determineConfigFilesFromArgs(String[] args, Map<String, String> envVars) {
        List<File> configFiles = new ArrayList<>();

        if (envVars.containsKey(ConfigUtils.CONFIG_FILES)) {
            for (String file : StringUtils.tokenizeToStringArray(envVars.get(ConfigUtils.CONFIG_FILES), ",")) {
                configFiles.add(new File(file));
            }
            return configFiles;
        }

        for (String arg : args) {
            String argValue = getArgumentValue(arg);
            if (isPropertyArgument(arg) && ConfigUtils.CONFIG_FILES.equals(getArgumentProperty(arg))) {
                for (String file : StringUtils.tokenizeToStringArray(argValue, ",")) {
                    configFiles.add(new File(file));
                }
            }
        }
        return configFiles;
    }
    /**
     * Determines the encoding to use for loading the configuration.
     *
     * @param args    The command-line arguments passed in.
     * @param envVars The environment variables converted to Flyway properties.
     * @return The encoding. (default: UTF-8)
     */
    private static String determineConfigurationFileEncoding(String[] args, Map<String, String> envVars) {
        if (envVars.containsKey(ConfigUtils.CONFIG_FILE_ENCODING)) {
            return envVars.get(ConfigUtils.CONFIG_FILE_ENCODING);
        }

        for (String arg : args) {
            if (isPropertyArgument(arg) && ConfigUtils.CONFIG_FILE_ENCODING.equals(getArgumentProperty(arg))) {
                return getArgumentValue(arg);
            }
        }

        return "UTF-8";
    }

    /**
     * Overrides the configuration from the config file with the properties passed in directly from the command-line.
     *
     * @param properties The properties to override.
     * @param args       The command-line arguments that were passed in.
     */
    /* private -> for testing*/
    static void overrideConfigurationWithArgs(Properties properties, String[] args) {
        for (String arg : args) {
            if (isPropertyArgument(arg)) {
                properties.put(getArgumentProperty(arg), getArgumentValue(arg));
            }
        }
    }

    /**
     * Checks whether this command-line argument tries to set a property.
     *
     * @param arg The command-line argument to check.
     * @return {@code true} if it does, {@code false} if not.
     */
    /* private -> for testing*/
    static boolean isPropertyArgument(String arg) {
        return arg.startsWith("-") && arg.contains("=");
    }

    /**
     * Retrieves the property this command-line argument tries to assign.
     *
     * @param arg The command-line argument to check, typically in the form -key=value.
     * @return The property.
     */
    /* private -> for testing*/
    static String getArgumentProperty(String arg) {
        int index = arg.indexOf("=");

        String argument = arg.substring(1, index);
    
        if (NON_FLYWAY_ARGS.contains(argument)) {
            return argument;
        }
        
        return "flyway." + argument;
    }

    /**
     * Retrieves the value this command-line argument tries to assign.
     *
     * @param arg The command-line argument to check, typically in the form -key=value.
     * @return The value or an empty string if no value is assigned.
     */
    /* private -> for testing*/
    static String getArgumentValue(String arg) {
        int index = arg.indexOf("=");

        if ((index < 0) || (index == arg.length())) {
            return "";
        }

        return arg.substring(index + 1);
    }

    /**
     * Determine the operations Flyway should execute.
     *
     * @param args The command-line arguments passed in.
     * @return The operations. An empty list if none.
     */
    private static List<String> determineOperations(String[] args) {
        List<String> operations = new ArrayList<>();

        for (String arg : args) {
            if (!arg.startsWith("-")) {
                operations.add(arg);
            }
        }

        return operations;
    }
}