/*
 * MiraXT - Secure Steganography & Cryptography Tool (CLI Version)
 * Copyright (C) 2026 Michael Janssen <m.janssen@lyrah.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	saltSize   = 16
	nonceSize  = 12
	iterations = 100000
	keyLen     = 32
)

// --- Banner ---

func printBanner() {
	banner := `
 ██████   ██████  ███                      █████ █████ ███████████
░░██████ ██████  ░░░                      ░░███ ░░███ ░█░░░███░░░█
 ░███░█████░███  ████  ████████   ██████   ░░███ ███  ░   ░███  ░ 
 ░███░░███ ░███ ░░███ ░░███░░███ ░░░░░███   ░░█████       ░███    
 ░███ ░░░  ░███  ░███  ░███ ░░░   ███████    ███░███      ░███    
 ░███      ░███  ░███  ░███      ███░░███   ███ ░░███     ░███    
 █████     █████ █████ █████    ░░████████ █████ █████    █████   
░░░░░     ░░░░░ ░░░░░ ░░░░░      ░░░░░░░░ ░░░░░ ░░░░░    ░░░░░    
                                                                 Version : 0.9-3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|S|e|c|u|r|e|_|S|t|e|g|a|n|o|g|r|a|p|h|y|_|&|_|C|r|y|p|t|o|g|r|a|p|h|y|_|T|o|o|l|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`
	fmt.Println(banner)
}

// --- Helper for Secure Password Input ---

func promptPassphrase(prompt string) string {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("\n[Error] Failed to read password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println() // New line after hidden password input
	return string(bytePassword)
}

// --- Encryption & Decryption ---

// deriveKey generates a cryptographic key from the passphrase and salt using PBKDF2
func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// encrypt secures plaintext using AES-256-GCM and a user-provided passphrase
func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey([]byte(passphrase), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Package structure: Salt + Nonce + Ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decrypt recovers plaintext from encrypted data using the passphrase
func decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltSize+nonceSize {
		return nil, errors.New("data too short")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key := deriveKey([]byte(passphrase), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// --- Steganography (LSB) ---

// embedData hides encrypted payload into the Least Significant Bits (LSB) of PNG channels
func embedData(img image.Image, data []byte) (*image.NRGBA, error) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	// 4-byte length header + actual data payload
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(data)))
	copy(payload[4:], data)

	totalBits := len(payload) * 8
	maxBits := width * height * 3 // 3 channels (R, G, B) per pixel

	if totalBits > maxBits {
		return nil, fmt.Errorf("image too small: needs %d bits, capacity is %d bits", totalBits, maxBits)
	}

	outImg := image.NewNRGBA(bounds)
	bitIdx := 0

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			r8, g8, b8, a8 := uint8(r>>8), uint8(g>>8), uint8(b>>8), uint8(a>>8)
			channels := []*uint8{&r8, &g8, &b8}

			for i := 0; i < 3; i++ {
				if bitIdx < totalBits {
					bytePos := bitIdx / 8
					bitPos := 7 - (bitIdx % 8)
					bit := (payload[bytePos] >> bitPos) & 1
					*channels[i] = (*channels[i] & 0xFE) | bit
					bitIdx++
				}
			}
			outImg.SetNRGBA(x, y, color.NRGBA{R: r8, G: g8, B: b8, A: a8})
		}
	}

	return outImg, nil
}

// extractData retrieves hidden payload from the image LSBs
func extractData(img image.Image) ([]byte, error) {
	bounds := img.Bounds()
	var bits []byte

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)
			bits = append(bits, r8&1, g8&1, b8&1)
		}
	}

	bitsToBytes := func(bitSlice []byte) []byte {
		bytes := make([]byte, len(bitSlice)/8)
		for i := 0; i < len(bytes); i++ {
			var b byte
			for j := 0; j < 8; j++ {
				b |= (bitSlice[i*8+j] & 1) << (7 - j)
			}
			bytes[i] = b
		}
		return bytes
	}

	if len(bits) < 32 {
		return nil, errors.New("no valid data found in image")
	}

	headerBytes := bitsToBytes(bits[:32])
	dataLen := binary.BigEndian.Uint32(headerBytes)

	totalNeededBits := (4 + int(dataLen)) * 8
	if len(bits) < totalNeededBits {
		return nil, errors.New("corrupted image data or incorrect length")
	}

	fullBytes := bitsToBytes(bits[:totalNeededBits])
	return fullBytes[4:], nil
}

// loadPNG opens and decodes a PNG image file
func loadPNG(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return png.Decode(file)
}

// --- CLI Application ---

func main() {
	// Print ASCII Banner at startup
	printBanner()

	mode := flag.String("mode", "", "Operation mode: 'hide' or 'extract'")
	imgFlag := flag.String("img", "", "Path to input PNG image")
	outFlag := flag.String("out", "output.png", "Path to output PNG image (for hide mode)")
	secretFlag := flag.String("secret", "", "Path to secret TXT file (for hide mode)")
	extractOutFlag := flag.String("extract-out", "", "Path to save extracted TXT file (optional, prints to terminal if empty)")
	passFlag := flag.String("pass", "", "Passphrase for encryption/decryption (optional, prompts interactively if omitted)")

	flag.Parse()

	if *mode == "" || *imgFlag == "" {
		progName := os.Args[0]

		fmt.Println("Error: Missing required arguments.")
		fmt.Println("\nUsage Examples:")
		fmt.Println("  Hide:")
		fmt.Printf("    %s -mode=hide -img=cover.png -out=stego.png -secret=secret.txt\n", progName)
		fmt.Println("  Extract:")
		fmt.Printf("    %s -mode=extract -img=stego.png\n", progName)
		fmt.Printf("    %s -mode=extract -img=stego.png -extract-out=recovered.txt\n", progName)
		os.Exit(1)
	}

	// Fallback to interactive password prompt if '-pass' flag is omitted
	passphrase := *passFlag
	if passphrase == "" {
		switch *mode {
		case "hide":
			passphrase = promptPassphrase("Enter encryption passphrase: ")
			confirm := promptPassphrase("Confirm encryption passphrase: ")
			if passphrase != confirm {
				fmt.Println("\n[Error] Passphrases do not match!")
				os.Exit(1)
			}
		case "extract":
			passphrase = promptPassphrase("Enter decryption passphrase: ")
		}
	}

	// Load image
	img, err := loadPNG(*imgFlag)
	if err != nil {
		fmt.Printf("[Error] Failed to load image: %v\n", err)
		os.Exit(1)
	}

	switch *mode {
	case "hide":
		if *secretFlag == "" {
			fmt.Println("[Error] Missing '-secret' file argument for hide mode.")
			os.Exit(1)
		}

		// Read secret text file
		secretBytes, err := os.ReadFile(*secretFlag)
		if err != nil {
			fmt.Printf("[Error] Failed to read secret file: %v\n", err)
			os.Exit(1)
		}

		// Encrypt
		encData, err := encrypt(secretBytes, passphrase)
		if err != nil {
			fmt.Printf("[Error] Encryption failed: %v\n", err)
			os.Exit(1)
		}

		// Embed into image
		stegoImg, err := embedData(img, encData)
		if err != nil {
			fmt.Printf("[Error] Steganography embedding failed: %v\n", err)
			os.Exit(1)
		}

		// Save output image
		outFile, err := os.Create(*outFlag)
		if err != nil {
			fmt.Printf("[Error] Failed to create output image: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()

		if err := png.Encode(outFile, stegoImg); err != nil {
			fmt.Printf("[Error] Failed to encode PNG: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[Success] Secret file '%s' hidden inside '%s' -> saved as '%s'.\n", *secretFlag, *imgFlag, *outFlag)

	case "extract":
		// Extract raw payload from image
		extractedData, err := extractData(img)
		if err != nil {
			fmt.Printf("[Error] Data extraction failed: %v\n", err)
			os.Exit(1)
		}

		// Decrypt payload
		decryptedBytes, err := decrypt(extractedData, passphrase)
		if err != nil {
			fmt.Println("[Error] Decryption failed (Wrong passphrase or invalid image data).")
			os.Exit(1)
		}

		// Output result
		if *extractOutFlag != "" {
			err := os.WriteFile(*extractOutFlag, decryptedBytes, 0644)
			if err != nil {
				fmt.Printf("[Error] Failed to write extracted file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[Success] Extracted message successfully saved to '%s'.\n", *extractOutFlag)
		} else {
			fmt.Println("\n[Success] Extracted Secret Message:")
			fmt.Println("--------------------------------------------------")
			fmt.Println(string(decryptedBytes))
			fmt.Println("--------------------------------------------------")
		}

	default:
		fmt.Printf("[Error] Unknown mode '%s'. Use 'hide' or 'extract'.\n", *mode)
		os.Exit(1)
	}
}
