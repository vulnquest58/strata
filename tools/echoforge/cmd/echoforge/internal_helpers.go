package main

import "fmt"

// printPhase prints a formatted pipeline phase header.
func printPhase(id, name, emoji string) {
	fmt.Printf("\n  %s ─── %s %s\n", colorDim("┌"), emoji, colorBold(name+" ("+id+")"))
}

// printResult prints an indented result line.
func printResult(msg string) {
	fmt.Printf("  %s %s\n", colorDim("│"), msg)
}

// printWarning prints a soft warning line to stdout (not stderr) to avoid PowerShell NativeCommandError.
func printWarning(source, msg string) {
	fmt.Printf("  %s  ⚠  %s: %s\n", colorDim("│"), colorWarn(source), colorDim(msg))
}

func colorBold(s string) string { return "\033[1m" + s + "\033[0m" }
func colorDim(s string) string  { return "\033[2m" + s + "\033[0m" }
func colorWarn(s string) string { return "\033[33m" + s + "\033[0m" }
