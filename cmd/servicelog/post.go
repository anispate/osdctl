package servicelog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/openshift-online/ocm-cli/pkg/arguments"
	"github.com/openshift-online/ocm-cli/pkg/dump"
	sdk "github.com/openshift-online/ocm-sdk-go"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/osdctl/internal/servicelog"
	"github.com/openshift/osdctl/internal/utils"
	"github.com/openshift/osdctl/pkg/printer"
	ocmutils "github.com/openshift/osdctl/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type PostCmdOptions struct {
	Message                  servicelog.Message
	ClustersFile             servicelog.ClustersFile
	Template                 string
	TemplateParams           []string
	Overrides                []string
	filterFiles              []string // Path to filter file
	filtersFromFile          string   // Contents of filterFiles
	filterParams             []string
	isDryRun                 bool
	skipPrompts              bool
	clustersFile             string
	InternalOnly             bool
	ClusterId                string
	SpellcheckExclusionsFile string
	spellcheckExclusions     []string

	// Messaged clusters
	successfulClusters map[string]string
	failedClusters     map[string]string
}

const documentationBaseURL = "https://docs.openshift.com"

func newPostCmd() *cobra.Command {
	var opts = PostCmdOptions{}
	postCmd := &cobra.Command{
		Use:   "post CLUSTER_ID",
		Short: "Post a service log to a cluster or list of clusters",
		Long: `Post a service log to a cluster or list of clusters

  Docs: https://docs.openshift.com/rosa/logging/sd-accessing-the-service-logs.html`,
		Example: `
  # Post a service log to a single cluster via a local file
  osdctl servicelog post ${CLUSTER_ID} -t ~/path/to/file.json

  # Post a service log to a single cluster via a remote URL, providing a parameter
  osdctl servicelog post ${CLUSTER_ID} -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/incident_resolved.json -p ALERT_NAME="alert"

  # Post an internal-only service log message
  osdctl servicelog post ${CLUSTER_ID} -i -p "MESSAGE=This is an internal message"

  # Post a short external message
  osdctl servicelog post ${CLUSTER_ID} -r "summary=External Message" -r "description=This is an external message" -r internal_only=False

  # Post a service log to a group of clusters, determined by an OCM query
  ocm list cluster -p search="cloud_provider.id is 'gcp' and managed='true' and state is 'ready'"
  osdctl servicelog post -q "cloud_provider.id is 'gcp' and managed='true' and state is 'ready'" -t file.json
`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.ClusterId = args[0]
			}
			return opts.Run() // Move spell check into Run
		},
	}

	// define flags
	postCmd.Flags().StringVarP(&opts.Template, "template", "t", "", "Message template file or URL")
	postCmd.Flags().StringArrayVarP(&opts.TemplateParams, "param", "p", opts.TemplateParams, "Specify a key-value pair (eg. -p FOO=BAR) to set/override a parameter value in the template.")
	postCmd.Flags().StringArrayVarP(&opts.Overrides, "override", "r", opts.Overrides, "Specify a key-value pair (eg. -r FOO=BAR) to replace a JSON key in the document, only supports string fields, specifying -r without -t or -i will use a default template with severity `Info` and internal_only=True unless these are also overridden.")
	postCmd.Flags().BoolVarP(&opts.isDryRun, "dry-run", "d", false, "Dry-run - print the service log about to be sent but don't send it.")
	postCmd.Flags().StringArrayVarP(&opts.filterParams, "query", "q", []string{}, "Specify a search query (eg. -q \"name like foo\") for a bulk-post to matching clusters.")
	postCmd.Flags().BoolVarP(&opts.skipPrompts, "yes", "y", false, "Skips all prompts.")
	postCmd.Flags().StringArrayVarP(&opts.filterFiles, "query-file", "f", []string{}, "File containing search queries to apply. All lines in the file will be concatenated into a single query. If this flag is called multiple times, every file's search query will be combined with logical AND.")
	postCmd.Flags().StringVarP(&opts.clustersFile, "clusters-file", "c", "", `Read a list of clusters to post the servicelog to. the format of the file is: {"clusters":["$CLUSTERID"]}`)
	postCmd.Flags().BoolVarP(&opts.InternalOnly, "internal", "i", false, "Internal only service log. Use MESSAGE for template parameter (eg. -p MESSAGE='My super secret message').")
	postCmd.Flags().StringVar(&opts.Message.Summary, "summary", "", "Summary of the service log")
	postCmd.Flags().StringVar(&opts.Message.Description, "description", "", "Description of the service log")

	return postCmd
}

func (o *PostCmdOptions) Init() error {
	userParameterNames = []string{}
	userParameterValues = []string{}
	o.successfulClusters = make(map[string]string)
	o.failedClusters = make(map[string]string)
	return nil
}

func (o *PostCmdOptions) Validate() error {
	if o.ClusterId == "" && len(o.filterParams) == 0 && o.clustersFile == "" {
		return fmt.Errorf("no cluster identifier has been found")
	}
	return nil
}

// CheckServiceLogsLastHour returns true if there were servicelogs sent in the past hour, otherwise false
func CheckServiceLogsLastHour(clusterId string) bool {
	timeStampToCompare := time.Now().Add(-time.Hour)
	serviceLogs, err := GetServiceLogsSince(clusterId, timeStampToCompare, false, false)
	if err != nil {
		log.Warnf("please verify that you are not sending a duplicate service log that has been recently sent - failed to fetch recent service logs: %v", err)
		return true
	}
	if len(serviceLogs) > 0 {
		for _, svclog := range serviceLogs {
			log.Warnf("A service log has been submitted in last hour\nDescription: %s", svclog.Description())
		}
		return true
	}
	return false
}

func (o *PostCmdOptions) Run() error {
	if err := o.Init(); err != nil {
		return err
	}
	if err := o.Validate(); err != nil {
		return err
	}
	if err := o.readSpellcheckExclusions(); err != nil {
		return err
	}

	o.parseUserParameters()
	overrideMap, err := o.parseOverrides()
	if err != nil {
		log.Fatalf("Error parsing overrides: %s", err)
	}

	o.readFilterFile()
	o.readTemplate()

	// Check spelling after template is loaded
	fmt.Println("Message after readTemplate:", o.Message) // Debug
	if err := o.checkSpelling(); err != nil {
		log.Fatal(err)
		return err
	}

	for k := range userParameterNames {
		o.replaceFlags(userParameterNames[k], userParameterValues[k])
	}

	for overrideKey, overrideValue := range overrideMap {
		err := o.overrideField(overrideKey, overrideValue)
		if err != nil {
			log.Fatalf("could not override '%s': %s", overrideKey, err)
		}
	}

	o.checkLeftovers([]string{"${CLUSTER_UUID}"})

	// Removed duplicate checkSpelling call

	ocmClient, err := ocmutils.CreateConnection()
	if err != nil {
		return err
	}
	defer func() {
		if err := ocmClient.Close(); err != nil {
			log.Errorf("Cannot close the ocmClient (possible memory leak): %q", err)
		}
	}()

	// Merge OCM filters from all custom filter-related flags
	if o.filtersFromFile != "" {
		if len(o.filterParams) != 0 {
			log.Warnf("Search queries were passed using both the '-q' and '-f' flags. This will apply logical AND between the queries, potentially resulting in no matches")
		}
		filters := strings.Join(strings.Split(strings.TrimSpace(o.filtersFromFile), "\n"), " ")
		o.filterParams = append(o.filterParams, filters)
	}

	// Combine existing OCM filters with any cluster id-related flags
	var queries []string
	if o.clustersFile != "" {
		contents, err := o.accessFile(o.clustersFile)
		if err != nil {
			return fmt.Errorf("cannot read file %s: %w", o.clustersFile, err)
		}
		if err := o.parseClustersFile(contents); err != nil {
			return fmt.Errorf("cannot parse file %s: %w", o.clustersFile, err)
		}
		for i := range o.ClustersFile.Clusters {
			cluster := o.ClustersFile.Clusters[i]
			queries = append(queries, ocmutils.GenerateQuery(cluster))
		}
	}
	if o.ClusterId != "" {
		queries = append(queries, ocmutils.GenerateQuery(o.ClusterId))
	}
	if len(queries) > 0 {
		if len(o.filterParams) > 0 {
			log.Warnf("A cluster identifier was passed with the '-q' flag. This will apply logical AND between the search query and the cluster given, potentially resulting in no matches")
		}
		o.filterParams = append(o.filterParams, strings.Join(queries, " or "))
	}

	if len(o.filterParams) > 0 {
		log.Debugf("applied filters: %v", o.filterParams)
	}

	clusters, err := ocmutils.ApplyFilters(ocmClient, o.filterParams)
	if err != nil {
		return fmt.Errorf("failed to search for clusters with provided filters (%v): %v", o.filterParams, err)
	} else if len(clusters) < 1 {
		return fmt.Errorf("no clusters match the given filters (%v)", o.filterParams)
	}

	log.Infoln("The following clusters match the given parameters:")
	if err := o.printClusters(clusters); err != nil {
		return fmt.Errorf("could not print matching clusters: %v", err)
	}

	// If sending a service log to one cluster, print recent service logs so that we can verify we aren't sending
	// duplicate messages in quick succession
	if len(clusters) == 1 {
		if term.IsTerminal(int(os.Stdout.Fd())) && CheckServiceLogsLastHour(clusters[0].ID()) {
			if !ocmutils.ConfirmPrompt() {
				return nil
			}
		}
	}

	log.Infoln("The following template will be sent:")
	if err := o.printTemplate(); err != nil {
		return fmt.Errorf("cannot read generated template: %w", err)
	}

	// If this is a dry-run, don't proceed further.
	if o.isDryRun {
		return nil
	}

	if !o.skipPrompts {
		if !ocmutils.ConfirmPrompt() {
			return nil
		}
	}

	// Handler if the program terminates abruptly
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan

		// perform final cleanup actions
		log.Error("program abruptly terminated, performing clean-up...")
		o.cleanUp(clusters)
		log.Fatal("servicelog post command terminated")
	}()

	// cluster type for which documentation link is provided in servicelog description
	docClusterType := getDocClusterType(o.Message.Description)

	for _, cluster := range clusters {
		request, err := o.createPostRequest(ocmClient, cluster)
		if err != nil {
			o.failedClusters[cluster.ExternalID()] = err.Error()
			continue
		}

		// if servicelog description contains a documentation link, verify that
		// documentation link matches the cluster product (rosa, dedicated)
		if !o.skipPrompts && docClusterType != "" {
			clusterType := cluster.Product().ID()

			if docClusterType != clusterType {
				log.Warn("The documentation mentioned in the servicelog is for '", docClusterType, "' while the product is '", clusterType, "'.")
				if !ocmutils.ConfirmPrompt() {
					log.Info("Skipping cluster ID: ", cluster.ID(), ", Name: ", cluster.Name())
					continue
				}
			}
		}

		response, err := ocmutils.SendRequest(request)
		if err != nil {
			o.failedClusters[cluster.ExternalID()] = err.Error()
			continue
		}

		o.check(response, o.Message)
	}

	o.printPostOutput()
	return nil
}

// if servicelog description contains documentation link, parse and return the cluster type from the url
func getDocClusterType(message string) string {

	if strings.Contains(message, documentationBaseURL) {
		pattern := `https://docs.openshift.com/([^/]+)/`
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(message)
		if len(match) >= 2 {
			productType := match[1]
			if productType == "dedicated" {
				// the documentation urls for osd use "dedicated" as the differentiator
				// e.g. https://docs.openshift.com/dedicated/welcome/index.html
				// for proper comparison with cluster product types, return "osd"
				// where "dedicated" is used in the documentation urls
				productType = "osd"
			}
			return productType
		}
	}
	return ""
}

func (o *PostCmdOptions) check(response *sdk.Response, clusterMessage servicelog.Message) {
	body := response.Bytes()
	if response.Status() < 400 {
		_, err := validateGoodResponse(body, clusterMessage)
		if err != nil {
			o.failedClusters[clusterMessage.ClusterUUID] = err.Error()
		} else {
			o.successfulClusters[clusterMessage.ClusterUUID] = fmt.Sprintf("Message has been successfully sent to %s", clusterMessage.ClusterUUID)
		}
	} else {
		badReply, err := validateBadResponse(body)
		if err != nil {
			o.failedClusters[clusterMessage.ClusterUUID] = err.Error()
		} else {
			o.failedClusters[clusterMessage.ClusterUUID] = badReply.Reason
		}
	}
}

// parseUserParameters parse all the '-p FOO=BAR' parameters and checks for syntax errors
func (o *PostCmdOptions) parseUserParameters() {
	for _, v := range o.TemplateParams {
		if !strings.Contains(v, "=") {
			log.Fatalf("Wrong syntax of '-p' flag. Please use it like this: '-p FOO=BAR'")
		}

		param := strings.SplitN(v, "=", 2)
		if param[0] == "" || param[1] == "" {
			log.Fatalf("Wrong syntax of '-p' flag. Please use it like this: '-p FOO=BAR'")
		}

		userParameterNames = append(userParameterNames, fmt.Sprintf("${%v}", param[0]))
		userParameterValues = append(userParameterValues, param[1])
	}
}

// parseOverides parses all the '-o FOO=BAR' overrides which replace items in the final JSON document
func (o *PostCmdOptions) parseOverrides() (map[string]string, error) {
	usageMessageError := errors.New("invalid syntax. Usage: '-r FOO=BAR'")
	overrideMap := make(map[string]string)

	for _, v := range o.Overrides {
		if !strings.Contains(v, "=") {
			return nil, usageMessageError
		}

		param := strings.SplitN(v, "=", 2)
		if param[0] == "" || param[1] == "" {
			return nil, usageMessageError
		}

		overrideMap[param[0]] = param[1]
	}

	return overrideMap, nil
}

func (o *PostCmdOptions) overrideField(overrideKey string, overrideValue string) (err error) {
	// Get a pointer, then the value of that pointer so that we can edit the fields
	rt := reflect.ValueOf(&o.Message).Elem()

	for i := 0; i < rt.NumField(); i++ {
		// Get JSON field name
		field := rt.Type().Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]

		if overrideKey == jsonName {
			// This shouldn't happen, but if it does we should make a nice error
			if !rt.Field(i).CanSet() {
				return fmt.Errorf("field cannot be modified")
			}

			kind := rt.Field(i).Kind()

			// Set the field to the overridden value, since we have a string
			// we may have to parse it to get the right type
			switch kind {
			case reflect.String:
				rt.Field(i).SetString(overrideValue)

			case reflect.Bool:
				overrideBool, err := strconv.ParseBool(overrideValue)
				if err != nil {
					return fmt.Errorf("couldn't parse bool: %s", err)
				}
				rt.Field(i).SetBool(overrideBool)

			default:
				return fmt.Errorf("overriding of type %s not implemented", kind)
			}

			return nil
		}
	}

	return fmt.Errorf("field does not exist")
}

// accessFile returns the contents of a local file or url, and any errors encountered
func (o *PostCmdOptions) accessFile(filePath string) ([]byte, error) {

	if utils.IsValidUrl(filePath) {
		urlPage, _ := url.Parse(filePath)
		if err := utils.IsOnline(*urlPage); err != nil {
			return nil, fmt.Errorf("host %q is not accessible", filePath)
		}
		return utils.CurlThis(urlPage.String())
	}

	filePath = filepath.Clean(filePath)
	if utils.FileExists(filePath) {
		// template is file on the disk
		file, err := os.ReadFile(filePath) //#nosec G304 -- Potential file inclusion via variable
		if err != nil {
			return file, fmt.Errorf("cannot read the file.\nError: %q", err)
		}
		return file, nil
	}
	if utils.FolderExists(filePath) {
		return nil, fmt.Errorf("the provided path %q is a directory, not a file", filePath)
	}
	return nil, fmt.Errorf("cannot read the file %q", filePath)
}

// parseClustersFile reads the clustrs file into a JSON struct
func (o *PostCmdOptions) parseClustersFile(jsonFile []byte) error {
	return json.Unmarshal(jsonFile, &o.ClustersFile)
}

// parseTemplate reads the template file into a JSON struct
func (o *PostCmdOptions) parseTemplate(jsonFile []byte) error {
	return json.Unmarshal(jsonFile, &o.Message)
}

// readTemplate loads the template into the Message variable
func (o *PostCmdOptions) readTemplate() {
	if o.InternalOnly {
		// fixed template for internal service logs
		messageTemplate := []byte(`
		{
			"severity": "Info",
			"service_name": "SREManualAction",
			"summary": "INTERNAL ONLY, DO NOT SHARE WITH CUSTOMER",
			"description": "${MESSAGE}",
			"internal_only": true
		}
		`)
		if err := o.parseTemplate(messageTemplate); err != nil {
			log.Fatalf("Cannot not parse the JSON internal message template.\nError: %q\n", err)
		}
		return
	}

	// If neither `-i` or `-t` is specified, but `-r` is specified at least once then use a pre-canned template
	if !o.InternalOnly && (o.Template == "") && (len(o.Overrides) != 0) {
		messageTemplate := []byte(`
		{
			"severity": "Info",
			"service_name": "SREManualAction",
			"internal_only": true
		}
		`)
		if err := o.parseTemplate(messageTemplate); err != nil {
			log.Fatalf("Cannot not parse the default message template.\nError: %q\n", err)
		}
		return
	}

	if o.Template == "" {
		log.Fatalf("Template file is not provided. Use '-t' to fix this.")
	}

	file, err := o.accessFile(o.Template)
	if err != nil { // check if this URL or file and if we can access it
		log.Fatal(err)
	}

	if err = o.parseTemplate(file); err != nil {
		log.Fatalf("Cannot not parse the JSON template.\nError: %q\n", err)
	}
}

func (o *PostCmdOptions) readFilterFile() {
	if len(o.filterFiles) < 1 {
		// No filterFiles specified in args
		return
	}

	for _, filterFile := range o.filterFiles {
		fileContents, err := o.accessFile(filterFile)
		if err != nil {
			log.Fatal(err)
		}

		if o.filtersFromFile == "" {
			o.filtersFromFile = "(" + strings.TrimSpace(string(fileContents)) + ")"
		} else {
			o.filtersFromFile = o.filtersFromFile + " and (" + strings.TrimSpace(string(fileContents)) + ")"
		}
	}
}

func (o *PostCmdOptions) FindLeftovers(s string) (matches []string) {
	r := regexp.MustCompile(`\${[^{}]*}`)
	matches = r.FindAllString(s, -1)
	return matches
}

func (o *PostCmdOptions) checkLeftovers(excludes []string) {
	unusedParameters, _ := o.Message.FindLeftovers()
	unusedParameters = append(unusedParameters, o.FindLeftovers(o.filtersFromFile)...)

	var numberOfMissingParameters int
	for _, v := range unusedParameters {
		// Ignore parameters in the exclude list, ie ${CLUSTER_UUID}, which will be replaced later for each cluster a servicelog is sent to

		if !slices.Contains(excludes, v) {
			numberOfMissingParameters++
			regex := strings.NewReplacer("${", "", "}", "")
			log.Errorf("The one of the template files is using '%s' parameter, but '--param' flag is not set for this one. Use '-p %v=\"FOOBAR\"' to fix this.", v, regex.Replace(v))
		}
	}
	if numberOfMissingParameters == 1 {
		log.Fatal("Please define this missing parameter properly.")
	} else if numberOfMissingParameters > 1 {
		log.Fatalf("Please define all %v missing parameters properly.", numberOfMissingParameters)
	}
}

func (o *PostCmdOptions) replaceFlags(flagName string, flagValue string) {
	if flagValue == "" {
		log.Fatalf("The selected template is using '%[1]s' parameter, but '%[1]s' flag was not set. Use '-p %[1]s=\"FOOBAR\"' to fix this.", flagName)
	}

	found := false
	if o.Message.SearchFlag(flagName) {
		found = true
		o.Message.ReplaceWithFlag(flagName, flagValue)
	}

	if strings.Contains(o.filtersFromFile, flagName) {
		found = true
		o.filtersFromFile = strings.ReplaceAll(o.filtersFromFile, flagName, flagValue)
	}

	if !found {
		log.Fatalf("The selected template is not using '%s' parameter, but '--param' flag was set. Do not use '-p %s=%s' to fix this.", flagName, flagName, flagValue)
	}
}

func (o *PostCmdOptions) printClusters(clusters []*v1.Cluster) (err error) {
	table := printer.NewTablePrinter(os.Stdout, 20, 1, 3, ' ')
	table.AddRow([]string{"Name", "ID", "State", "Version", "Cloud Provider", "Region"})
	for _, cluster := range clusters {
		table.AddRow([]string{cluster.Name(), cluster.ID(), string(cluster.State()), cluster.OpenshiftVersion(), cluster.CloudProvider().ID(), cluster.Region().ID()})
	}

	// Add empty row for readability
	table.AddRow([]string{})
	return table.Flush()
}

func (o *PostCmdOptions) printTemplate() (err error) {
	exampleMessage, err := json.Marshal(o.Message)
	if err != nil {
		return err
	}
	return dump.Pretty(os.Stdout, exampleMessage)
}

func (o *PostCmdOptions) createPostRequest(ocmClient *sdk.Connection, cluster *v1.Cluster) (request *sdk.Request, err error) {
	// Create and populate the request:
	request = ocmClient.Post()
	err = arguments.ApplyPathArg(request, targetAPIPath)
	if err != nil {
		return nil, fmt.Errorf("cannot parse API path '%s': %v", targetAPIPath, err)
	}

	o.Message.ClusterUUID = cluster.ExternalID()
	o.Message.ClusterID = cluster.ID()
	o.Message.InternalOnly = o.InternalOnly
	if subscription := cluster.Subscription(); subscription != nil {
		o.Message.SubscriptionID = cluster.Subscription().ID()
	}

	messageBytes, err := json.Marshal(o.Message)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal template to json: %v", err)
	}

	request.Bytes(messageBytes)
	return request, nil
}

// listMessagedClusters prints all the clusters a service log was tried to be posted.
func (o *PostCmdOptions) listMessagedClusters(clusters map[string]string) error {
	table := printer.NewTablePrinter(os.Stdout, 20, 1, 3, ' ')
	table.AddRow([]string{"ID", "Status"})

	for id, status := range clusters {
		table.AddRow([]string{id, status})
	}

	// New row for better readability
	table.AddRow([]string{})

	return table.Flush()
}

// printPostOutput prints the main servicelog post output.
func (o *PostCmdOptions) printPostOutput() {
	output := fmt.Sprintf("Success: %d, Failed: %d\n", len(o.successfulClusters), len(o.failedClusters))
	log.Infoln(output + "\n")

	// Print if any service logs were successfully sent
	if len(o.successfulClusters) > 0 {
		log.Infoln("Successful clusters:")
		if err := o.listMessagedClusters(o.successfulClusters); err != nil {
			log.Fatalf("Cannot list successful clusters: %q", err)
		}
	}

	// Print if there were failures while sending service logs
	if len(o.failedClusters) > 0 {
		log.Infoln("Failed clusters:")
		if err := o.listMessagedClusters(o.failedClusters); err != nil {
			log.Fatalf("Cannot list failed clusters: %q", err)
		}
	}
}

// cleanUp performs final actions in case of program termination.
func (o *PostCmdOptions) cleanUp(clusters []*v1.Cluster) {
	for _, cluster := range clusters {
		if _, ok := o.successfulClusters[cluster.ExternalID()]; !ok {
			o.failedClusters[cluster.ExternalID()] = "cannot send message due to program interruption"
		}
	}

	o.printPostOutput()
}

// Dictionary loaded dynamically
var dictionary map[string]bool

func loadDictionary() error {
	if dictionary != nil {
		return nil
	}
	dictionary = make(map[string]bool)
	dictPath := "/usr/share/dict/words" // Common on macOS
	data, err := os.ReadFile(dictPath)
	if err != nil {
		return fmt.Errorf("failed to load dictionary from %s: %w", dictPath, err)
	}
	for _, word := range strings.Split(string(data), "\n") {
		word = strings.TrimSpace(word)
		if word != "" {
			dictionary[strings.ToLower(word)] = true
		}
	}
	fmt.Printf("Loaded %d words from dictionary\n", len(dictionary))
	return nil
}

func (o *PostCmdOptions) checkSpelling() error {
	// Load dictionary
	if err := loadDictionary(); err != nil {
		log.Warnf("Proceeding without dictionary: %v", err)
		dictionary = make(map[string]bool) // Fallback to empty dictionary
	}

	red := color.New(color.FgHiRed)
	boldRed := red.Add(color.Underline)

	fieldsToCheck := []string{
		o.Message.Summary,
		o.Message.Description,
	}

	var corrections []string
	for _, fieldValue := range fieldsToCheck {
		if fieldValue == "" {
			continue
		}

		fmt.Println("Checking field:", fieldValue)
		words := splitIntoWords(fieldValue)
		p1 := regexp.MustCompile(`^[.,:'"]`)
		p2 := regexp.MustCompile(`[.,:'"]$`)

		for _, word := range words {
			nw := p1.ReplaceAll([]byte(word), []byte(""))
			nw = p2.ReplaceAll(nw, []byte(""))
			cleanWord := string(nw)

			fmt.Printf("Word: %q ", cleanWord)

			if strings.HasPrefix(cleanWord, "http") {
				fmt.Printf("(skipped URL) %s ", cleanWord)
				continue
			}

			isExcluded := slices.ContainsFunc(o.spellcheckExclusions, func(excluded string) bool {
				return strings.EqualFold(excluded, cleanWord)
			})
			if isExcluded {
				fmt.Printf("(excluded) %s ", cleanWord)
				continue
			}

			// Check if word is in dictionary
			lowerWord := strings.ToLower(cleanWord)
			isCorrect := dictionary[lowerWord]
			suggestion := ""
			if !isCorrect {
				// Use heuristics and Levenshtein distance if not in dictionary
				if isLikelyTypo(cleanWord) || !isCorrect {
					suggestion = suggestCorrection(lowerWord)
					fmt.Printf("(typo detected, suggestion: %q) ", suggestion)
					if suggestion != "" && suggestion != cleanWord && suggestion != lowerWord {
						corrections = append(corrections, fmt.Sprintf("Original: %s (Suggested: %s)", cleanWord, suggestion))
						boldRed.Printf("%s ", cleanWord)
					} else {
						fmt.Printf("%s ", cleanWord)
					}
				} else {
					fmt.Printf("(not in dict) %s ", cleanWord)
				}
			} else {
				fmt.Printf("%s ", cleanWord)
			}
		}
		fmt.Println()
	}

	if len(corrections) > 0 {
		summary := fmt.Sprintf("Spelling errors detected in %d words:\n%s", len(corrections), strings.Join(corrections, "\n"))
		return fmt.Errorf(summary)
	}
	fmt.Println("No spelling errors detected.")
	return nil
}

// isLikelyTypo detects obvious typos
func isLikelyTypo(word string) bool {
	lowerWord := strings.ToLower(word)
	length := len(lowerWord)

	// Short words (< 3) are suspicious
	if length < 3 {
		return true
	}

	// Count vowels and consonants
	vowels := 0
	consonants := 0
	for _, r := range lowerWord {
		if strings.ContainsRune("aeiou", r) {
			vowels++
		} else if unicode.IsLetter(r) {
			consonants++
		}
	}

	// No vowels in longer words
	if vowels == 0 && length > 3 {
		return true
	}

	// High consonant-to-vowel ratio
	if consonants > vowels*2 && length > 5 {
		return true
	}

	// Repeated letters (3+)
	for i := 0; i < len(word)-2; i++ {
		if word[i] == word[i+1] && word[i+1] == word[i+2] {
			return true
		}
	}

	// Mixed numbers and letters
	hasLetters := false
	hasNumbers := false
	for _, r := range word {
		if unicode.IsLetter(r) {
			hasLetters = true
		}
		if unicode.IsDigit(r) {
			hasNumbers = true
		}
	}
	if hasLetters && hasNumbers && length > 4 {
		return true
	}

	// Consecutive consonant runs
	consonantRun := 0
	for _, r := range lowerWord {
		if !strings.ContainsRune("aeiou", r) && unicode.IsLetter(r) {
			consonantRun++
			if consonantRun > 3 {
				return true
			}
		} else {
			consonantRun = 0
		}
	}

	return false
}

// suggestCorrection uses Levenshtein distance and heuristics
func suggestCorrection(word string) string {
	cleaned := cleanWord(word)
	if cleaned == "" {
		return word
	}

	// Try common suffixes first
	if strings.HasSuffix(cleaned, "tion") && len(cleaned) > 6 {
		if dictionary[cleaned] {
			return cleaned
		}
		for dictWord := range dictionary {
			if strings.HasSuffix(dictWord, "tion") && levenshteinDistance(cleaned, dictWord) <= 3 {
				return dictWord
			}
		}
	}
	if strings.HasSuffix(cleaned, "ed") && len(cleaned) > 5 {
		if dictionary[cleaned] {
			return cleaned
		}
		for dictWord := range dictionary {
			if strings.HasSuffix(dictWord, "ed") && levenshteinDistance(cleaned, dictWord) <= 3 {
				return dictWord
			}
		}
	}

	// General Levenshtein search
	bestMatch := ""
	minDistance := 3 // Threshold for suggestion
	for dictWord := range dictionary {
		dist := levenshteinDistance(cleaned, dictWord)
		if dist < minDistance {
			minDistance = dist
			bestMatch = dictWord
		}
	}
	if bestMatch != "" {
		return bestMatch
	}
	return cleaned
}

// cleanWord removes numbers and collapses repeated letters
func cleanWord(word string) string {
	var cleanBuilder strings.Builder
	for _, r := range strings.ToLower(word) {
		if unicode.IsLetter(r) {
			cleanBuilder.WriteRune(r)
		}
	}
	cleaned := cleanBuilder.String()
	if cleaned == "" {
		return ""
	}

	var noRepeats strings.Builder
	lastChar := rune(0)
	repeatCount := 0
	for _, r := range cleaned {
		if r == lastChar {
			repeatCount++
			if repeatCount < 2 {
				noRepeats.WriteRune(r)
			}
		} else {
			noRepeats.WriteRune(r)
			lastChar = r
			repeatCount = 0
		}
	}
	return noRepeats.String()
}

// levenshteinDistance calculates edit distance
func levenshteinDistance(s1, s2 string) int {
	if s1 == s2 {
		return 0
	}
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	dp := make([][]int, len(s1)+1)
	for i := range dp {
		dp[i] = make([]int, len(s2)+1)
		dp[i][0] = i
	}
	for j := range dp[0] {
		dp[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
		}
	}
	return dp[len(s1)][len(s2)]
}

func min(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// splitIntoWords splits the input string into words while preserving expected punctuation
func splitIntoWords(input string) []string {
	var words []string
	var currentWord strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || isExpectedPunctuation(r) || r == '-' {
			currentWord.WriteRune(r)
		} else if unicode.IsSpace(r) {
			if currentWord.Len() > 0 {
				words = append(words, currentWord.String())
				currentWord.Reset()
			}
		}
	}
	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}
	return words
}

// isExpectedPunctuation checks if the rune is an expected punctuation mark
func isExpectedPunctuation(r rune) bool {
	expectedPunctuation := []rune{',', '.', '\'', ':', ';', '!', '?'}
	for _, p := range expectedPunctuation {
		if r == p {
			return true
		}
	}
	return false
}

func (o *PostCmdOptions) checkSpellingWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout) // Create a context with a timeout
	defer cancel()

	resultChan := make(chan error, 1) // Channel to receive the result of the spell-checking

	go func() {
		resultChan <- o.checkSpelling() //Run the spell-checking in a goroutine
	}()

	// Wait for the result or timeout
	select {
	case err := <-resultChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("spell-checking timed out after %v", timeout)
	}
}

func (o *PostCmdOptions) readSpellcheckExclusions() error {
	defaultExclusionsFile := "/Users/anishpatel/github_repos/osdctl/cmd/servicelog/spellcheck-exclusions.txt" // Set your default path
	filePath := o.SpellcheckExclusionsFile
	if filePath == "" {
		filePath = defaultExclusionsFile
		fmt.Println("Using default spellcheck exclusions file:", filePath)
	} else {
		fmt.Println("Using specified spellcheck exclusions file:", filePath)
	}

	contents, err := o.accessFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read spellcheck exclusions file: %w", err)
	}
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			o.spellcheckExclusions = append(o.spellcheckExclusions, line)
		}
	}
	fmt.Println("Loaded spellcheck exclusions:", o.spellcheckExclusions)
	return nil
}

func ConfirmPrompt(prompt string) bool {
	fmt.Print(prompt)
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
