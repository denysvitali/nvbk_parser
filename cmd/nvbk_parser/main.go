package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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

	nvGetCmd = &cobra.Command{
		Use:   "nv-get <id> [file]",
		Short: "Extract a numeric NV item by ID",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  runNVGet,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nvbk_parser.yaml)")
	rootCmd.PersistentFlags().StringP("file", "f", "", "OEMNVBK file to parse")
	rootCmd.PersistentFlags().StringP("format", "o", "table", "output format: table, json")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().BoolP("verify", "", false, "show SHA-256 payload verification details")

	_ = viper.BindPFlag("file", rootCmd.PersistentFlags().Lookup("file"))
	_ = viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("verify", rootCmd.PersistentFlags().Lookup("verify"))

	rootCmd.AddCommand(infoCmd, listCmd, nvGetCmd)
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
	fmt.Printf("%s 0x%02x\n", keyStyle.Render("Header flg: "), f.Header.HeaderFlag)
	fmt.Printf("%s %s\n", keyStyle.Render("Build time: "), f.Header.BuildTime)
	fmt.Printf("%s %d\n", keyStyle.Render("Total:      "), f.Header.Total)
	fmt.Printf("%s %d\n", keyStyle.Render("Valid:      "), f.Header.Valid)
	fmt.Printf("%s %v\n", keyStyle.Render("Verify:     "), f.Header.Verify)

	showVerify := viper.GetBool("verify")

	rows := [][]string{
		{"#", "Start", "Sectors", "RF ID", "RF name", "Hint", "Items"},
	}
	if showVerify {
		rows[0] = append(rows[0], "Verified")
	}
	for _, sf := range f.SubFiles {
		rfName := nvbk.LookupRFIDName(sf.RFID)
		if rfName == "" {
			rfName = "-"
		}
		row := []string{
			fmt.Sprintf("%d", sf.Index),
			fmt.Sprintf("0x%x", sf.StartSector),
			fmt.Sprintf("%d", sf.NumSectors),
			fmt.Sprintf("0x%02x", sf.RFID),
			rfName,
			fmt.Sprintf("%d", sf.CountHint),
			fmt.Sprintf("%d", sf.ItemCount),
		}
		if showVerify {
			verified := "no"
			if sf.Verified {
				verified = "yes"
			}
			row = append(row, verified)
		}
		rows = append(rows, row)
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
		var out []map[string]any
		for _, sf := range f.SubFiles {
			for _, e := range sf.Entries {
				out = append(out, map[string]any{
					"sub_file": sf.Index,
					"type":     "entry",
					"name":     e.Name,
					"tag":      fmt.Sprintf("0x%08x", e.Tag),
					"size":     len(e.Data),
				})
			}
			for _, it := range sf.Items {
				name := it.Name
				if name == "" {
					name = nvbk.LookupNVItemName(it.ID)
				}
				if name == "" {
					name = fmt.Sprintf("NV ITEM %05d", it.ID)
				}
				out = append(out, map[string]any{
					"sub_file": sf.Index,
					"type":     "nv_item",
					"name":     name,
					"id":       it.ID,
					"size":     len(it.Data),
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
		{"Sub", "Name", "Tag / ID", "Size"},
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
		for _, it := range sf.Items {
			name := it.Name
			if name == "" {
				name = nvbk.LookupNVItemName(it.ID)
			}
			if name == "" {
				name = fmt.Sprintf("NV ITEM %05d", it.ID)
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", sf.Index),
				name,
				fmt.Sprintf("%d", it.ID),
				fmt.Sprintf("%d", len(it.Data)),
			})
		}
	}

	if len(rows) == 1 {
		fmt.Println("No path-based entries or numeric NV items were parsed from this image.")
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

func runNVGet(cmd *cobra.Command, args []string) error {
	setupLogging()

	id, err := strconv.ParseUint(args[0], 0, 16)
	if err != nil {
		return fmt.Errorf("invalid NV item ID %q: %w", args[0], err)
	}

	path, err := targetPath(args[1:])
	if err != nil {
		return err
	}

	f, err := nvbkparser.ReadFile(path)
	if err != nil {
		return err
	}

	subFileIdx, data := nvbkparser.FindNVItem(f, uint16(id))
	if subFileIdx < 0 {
		return fmt.Errorf("NV item %d not found", id)
	}

	format := strings.ToLower(viper.GetString("format"))
	switch format {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"id":       id,
			"sub_file": subFileIdx,
			"size":     len(data),
			"hex":      hex.EncodeToString(data),
		})
	case "table", "":
		fmt.Printf("NV item %d (sub-file %d, %d bytes):\n", id, subFileIdx, len(data))
		for i := 0; i < len(data); i += 16 {
			end := min(i+16, len(data))
			fmt.Printf("%04x  %s\n", i, hex.EncodeToString(data[i:end]))
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}
