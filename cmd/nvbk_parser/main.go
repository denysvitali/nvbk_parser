package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	nvbkparser "github.com/denysvitali/nvbk_parser/pkg"
	"github.com/denysvitali/nvbk_parser/pkg/nvbk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "nvbk_parser",
		Short: "Parse OnePlus/Qualcomm OEMNVBK images",
		Long:  `A parser and inspector for Oppo's / OnePlus's static_nvbk and dynamic_nvbk partitions.`,
		RunE:  runInfo,
	}

	infoCmd = &cobra.Command{
		Use:   "info [file]",
		Short: "Show header information",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runInfo,
	}

	listCmd = &cobra.Command{
		Use:   "list [file]",
		Short: "List parsed NV items",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runList,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nvbk_parser.yaml)")
	rootCmd.PersistentFlags().StringP("file", "f", "", "OEMNVBK file to parse")
	rootCmd.PersistentFlags().StringP("format", "o", "table", "output format: table, json")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")

	_ = viper.BindPFlag("file", rootCmd.PersistentFlags().Lookup("file"))
	_ = viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	rootCmd.AddCommand(infoCmd, listCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigName(".nvbk_parser")
	}

	viper.SetEnvPrefix("NVBK")
	viper.AutomaticEnv()

	_ = viper.ReadInConfig()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setupLogging() {
	if viper.GetBool("verbose") {
		nvbkparser.Log.SetLevel(logrus.DebugLevel)
	} else {
		nvbkparser.Log.SetLevel(logrus.WarnLevel)
	}
}

func targetPath(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	f := viper.GetString("file")
	if f == "" {
		return "", fmt.Errorf("no input file specified (use --file or positional argument)")
	}
	return f, nil
}

func runInfo(cmd *cobra.Command, args []string) error {
	setupLogging()
	path, err := targetPath(args)
	if err != nil {
		return err
	}

	f, err := nvbkparser.ReadFile(path)
	if err != nil {
		return err
	}

	format := strings.ToLower(viper.GetString("format"))
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f.Header)
	case "table", "":
		return renderInfoTable(f)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

func renderInfoTable(f *nvbk.NVBKFile) error {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F1F"))
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5F87FF"))

	fmt.Println(titleStyle.Render("OEMNVBK Header"))
	fmt.Printf("%s %s\n", keyStyle.Render("Magic:      "), f.Header.Magic)
	fmt.Printf("%s %02x %02x %02x %02x\n", keyStyle.Render("Version:    "),
		f.Header.Version[0], f.Header.Version[1], f.Header.Version[2], f.Header.Version[3])
	fmt.Printf("%s %d\n", keyStyle.Render("Sub-files:  "), f.Header.SubFileCount)
	fmt.Printf("%s 0x%x\n", keyStyle.Render("Table off:  "), f.Header.TableOffset)
	fmt.Printf("%s %s\n", keyStyle.Render("Build time: "), f.Header.BuildTime)
	fmt.Printf("%s %d\n", keyStyle.Render("Total:      "), f.Header.Total)
	fmt.Printf("%s %d\n", keyStyle.Render("Valid:      "), f.Header.Valid)
	fmt.Printf("%s %v\n", keyStyle.Render("Verify:     "), f.Header.Verify)

	rows := [][]string{
		{"#", "Start", "Sectors", "RF ID", "Hint", "Items"},
	}
	for _, sf := range f.SubFiles {
		rows = append(rows, []string{
			fmt.Sprintf("%d", sf.Index),
			fmt.Sprintf("0x%x", sf.StartSector),
			fmt.Sprintf("%d", sf.NumSectors),
			fmt.Sprintf("0x%02x", sf.RFID),
			fmt.Sprintf("%d", sf.CountHint),
			fmt.Sprintf("%d", sf.ItemCount),
		})
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == 0 {
				return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F1F"))
			}
			return lipgloss.NewStyle()
		})

	fmt.Println(t.Render())
	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	setupLogging()
	path, err := targetPath(args)
	if err != nil {
		return err
	}

	f, err := nvbkparser.ReadFile(path)
	if err != nil {
		return err
	}

	format := strings.ToLower(viper.GetString("format"))
	switch format {
	case "json":
		var out []map[string]interface{}
		for _, sf := range f.SubFiles {
			for _, e := range sf.Entries {
				out = append(out, map[string]interface{}{
					"sub_file": sf.Index,
					"name":     e.Name,
					"tag":      fmt.Sprintf("0x%08x", e.Tag),
					"size":     len(e.Data),
				})
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "table", "":
		return renderListTable(f)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

func renderListTable(f *nvbk.NVBKFile) error {
	rows := [][]string{
		{"Sub", "Name", "Tag", "Size"},
	}
	for _, sf := range f.SubFiles {
		for _, e := range sf.Entries {
			name := e.Name
			if name == "" {
				name = "(none)"
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", sf.Index),
				name,
				fmt.Sprintf("0x%08x", e.Tag),
				fmt.Sprintf("%d", len(e.Data)),
			})
		}
	}

	if len(rows) == 1 {
		fmt.Println("No path-based entries were parsed from this image.")
		return nil
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == 0 {
				return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5F1F"))
			}
			return lipgloss.NewStyle()
		})

	fmt.Println(t.Render())
	return nil
}
