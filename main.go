/*
 * MiraXT - Secure Steganography & Cryptography Tool
 * Copyright (C) 2026 MiraXT Contributors
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
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	nonceSize  = 12
	iterations = 100000
	keyLen     = 32
)

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

// --- TUI Application ---

func main() {
	app := tview.NewApplication()

	pages := tview.NewPages()
	statusBox := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	statusBox.SetBorder(true).SetTitle(" Status / Log ")

	// --- Hide Form Page ---
	hideForm := tview.NewForm()
	var hImg, hOut, hSecretFile, hPass string

	hideForm.AddInputField("Input Image (PNG):", "", 40, nil, func(text string) { hImg = text })
	hideForm.AddInputField("Output Image (PNG):", "output.png", 40, nil, func(text string) { hOut = text })
	hideForm.AddInputField("Secret File (.txt):", "", 40, nil, func(text string) { hSecretFile = text })
	hideForm.AddPasswordField("Passphrase:", "", 40, '*', func(text string) { hPass = text })

	hideForm.AddButton("Encrypt & Hide", func() {
		if hImg == "" || hOut == "" || hSecretFile == "" || hPass == "" {
			statusBox.SetText("[red]Error: All fields must be filled out.[-]")
			return
		}

		img, err := loadPNG(hImg)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Error loading image: %v[-]", err))
			return
		}

		// Read secret content directly from file
		secretBytes, err := os.ReadFile(hSecretFile)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Error reading secret file: %v[-]", err))
			return
		}

		encData, err := encrypt(secretBytes, hPass)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Encryption error: %v[-]", err))
			return
		}

		stegoImg, err := embedData(img, encData)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Steganography error: %v[-]", err))
			return
		}

        outFile, err := os.Create(hOut)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Error creating output file: %v[-]", err))
			return
		}
		defer outFile.Close()

		if err := png.Encode(outFile, stegoImg); err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Error saving PNG: %v[-]", err))
			return
		}

		statusBox.SetText(fmt.Sprintf("[green]Success! Secret file hidden securely in '%s'.[-]", hOut))
	})
	hideForm.AddButton("Quit", func() {
		app.Stop()
	})
	hideForm.SetBorder(true).SetTitle(" MiraXT - Hide Secret Message ")

	// --- Extract Form Page ---
	extractForm := tview.NewForm()
	var eImg, ePass string

	extractForm.AddInputField("Stego Image (PNG):", "", 40, nil, func(text string) { eImg = text })
	extractForm.AddPasswordField("Passphrase:", "", 40, '*', func(text string) { ePass = text })

	extractForm.AddButton("Extract & Decrypt", func() {
		if eImg == "" || ePass == "" {
			statusBox.SetText("[red]Error: All fields must be filled out.[-]")
			return
		}

		img, err := loadPNG(eImg)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Error loading image: %v[-]", err))
			return
		}

		extractedData, err := extractData(img)
		if err != nil {
			statusBox.SetText(fmt.Sprintf("[red]Extraction error: %v[-]", err))
			return
		}

		decryptedText, err := decrypt(extractedData, ePass)
		if err != nil {
			statusBox.SetText("[red]Decryption failed (Wrong passphrase or invalid image).[-]")
			return
		}

		statusBox.SetText(fmt.Sprintf("[green]Extracted Message:[-] %s", string(decryptedText)))
	})
	extractForm.AddButton("Quit", func() {
		app.Stop()
	})
	extractForm.SetBorder(true).SetTitle(" MiraXT - Extract Secret Message ")

	pages.AddPage("hide", hideForm, true, true)
	pages.AddPage("extract", extractForm, true, false)

	menu := tview.NewList().
		AddItem("Hide Message", "Encrypt text file into a PNG", '1', func() {
			pages.SwitchToPage("hide")
		}).
		AddItem("Extract Message", "Decrypt text from a PNG", '2', func() {
			pages.SwitchToPage("extract")
		}).
		AddItem("Quit", "Exit application", 'q', func() {
			app.Stop()
		})
	menu.SetBorder(true).SetTitle(" MiraXT Menu ")

	flex := tview.NewFlex().
		AddItem(menu, 25, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(pages, 0, 3, true).
			AddItem(statusBox, 6, 1, false), 0, 3, false)

	// Global Input Handler to toggle focus using the Tab key between Menu and Active Form
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab {
			if app.GetFocus() == menu {
				app.SetFocus(pages)
			} else {
				app.SetFocus(menu)
			}
			return nil
		}
		return event
	})

	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
