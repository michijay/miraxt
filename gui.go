/*
 * MiraXT - Secure Steganography & Cryptography Tool (GUI Version)
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
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	nonceSize  = 12
	iterations = 100000
	keyLen     = 32
)

// --- Custom Theme to fix disabled text color in Dark Mode ---
type customTheme struct {
	fyne.Theme
}

func (c *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Force brighter text color for disabled elements in dark mode so it's readable
	if name == theme.ColorNameDisabled {
		return color.RGBA{R: 220, G: 220, B: 220, A: 255}
	}
	return c.Theme.Color(name, variant)
}

// --- Crypto & Steganography Core ---

func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

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

	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

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

func embedData(img image.Image, data []byte) (*image.NRGBA, error) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(data)))
	copy(payload[4:], data)

	totalBits := len(payload) * 8
	maxBits := width * height * 3

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

func loadPNG(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return png.Decode(file)
}

// --- Fyne GUI Application ---

func main() {
	// Force Dark Mode appearance for the application
	os.Setenv("FYNE_THEME", "dark")

	myApp := app.NewWithID("com.miraxt.gui")
	// Apply custom theme to adjust disabled/output text readability
	myApp.Settings().SetTheme(&customTheme{Theme: theme.DefaultTheme()})

	myWindow := myApp.NewWindow("MiraXT - Secure Steganography")
	myWindow.Resize(fyne.NewSize(700, 600))

	// Status label for feedback
	statusLabel := widget.NewLabel("Status: Ready")
	statusLabel.Alignment = fyne.TextAlignCenter

	// --- TAB 1: Hide Mode ---
	inputImgEntry := widget.NewEntry()
	inputImgEntry.SetPlaceHolder("Path to cover image (.png)")
	btnBrowseImg := widget.NewButton("Browse", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				inputImgEntry.SetText(reader.URI().Path())
			}
		}, myWindow)
	})

	secretFileEntry := widget.NewEntry()
	secretFileEntry.SetPlaceHolder("Path to secret text file (.txt)")
	btnBrowseSecret := widget.NewButton("Browse", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				secretFileEntry.SetText(reader.URI().Path())
			}
		}, myWindow)
	})

	outputImgEntry := widget.NewEntry()
	outputImgEntry.SetText("stego_output.png")

	hidePassEntry := widget.NewPasswordEntry()
	hidePassEntry.SetPlaceHolder("Enter encryption passphrase")

	btnHide := widget.NewButton("Encrypt & Hide Secret", func() {
		if inputImgEntry.Text == "" || secretFileEntry.Text == "" || hidePassEntry.Text == "" {
			statusLabel.SetText("Error: Please fill in all required fields!")
			return
		}

		img, err := loadPNG(inputImgEntry.Text)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error loading image: %v", err))
			return
		}

		secretBytes, err := os.ReadFile(secretFileEntry.Text)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error reading secret file: %v", err))
			return
		}

		encData, err := encrypt(secretBytes, hidePassEntry.Text)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Encryption error: %v", err))
			return
		}

		stegoImg, err := embedData(img, encData)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Steganography error: %v", err))
			return
		}

		outFile, err := os.Create(outputImgEntry.Text)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error creating output file: %v", err))
			return
		}
		defer outFile.Close()

		if err := png.Encode(outFile, stegoImg); err != nil {
			statusLabel.SetText(fmt.Sprintf("Error saving PNG: %v", err))
			return
		}

		statusLabel.SetText("Success! Secret file securely hidden in image.")
		dialog.ShowInformation("Success", "Message encrypted and embedded successfully!", myWindow)
	})

	hideContainer := container.NewVBox(
		widget.NewLabelWithStyle("Hide Secret Message in PNG", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Cover Image (PNG):"),
		container.NewBorder(nil, nil, nil, btnBrowseImg, inputImgEntry),
		widget.NewLabel("Secret Text File (.txt):"),
		container.NewBorder(nil, nil, nil, btnBrowseSecret, secretFileEntry),
		widget.NewLabel("Output Image (.png):"),
		outputImgEntry,
		widget.NewLabel("Passphrase:"),
		hidePassEntry,
		widget.NewSeparator(),
		btnHide,
	)

    // --- TAB 2: Extract Mode ---
	extractImgEntry := widget.NewEntry()
	extractImgEntry.SetPlaceHolder("Path to stego image (.png)")
	btnBrowseExtract := widget.NewButton("Browse", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				extractImgEntry.SetText(reader.URI().Path())
			}
		}, myWindow)
	})

	extractPassEntry := widget.NewPasswordEntry()
	extractPassEntry.SetPlaceHolder("Enter decryption passphrase")

	// Enlarged text area for extracted results
	extractedResultBox := widget.NewMultiLineEntry()
	extractedResultBox.SetPlaceHolder("Extracted message will appear here...")
	extractedResultBox.Disable()

	extractedScroll := container.NewVScroll(extractedResultBox)
	extractedScroll.SetMinSize(fyne.NewSize(600, 160))

	btnExtract := widget.NewButton("Extract & Decrypt Message", func() {
		if extractImgEntry.Text == "" || extractPassEntry.Text == "" {
			statusLabel.SetText("Error: Image and passphrase are required!")
			return
		}

		img, err := loadPNG(extractImgEntry.Text)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error loading image: %v", err))
			return
		}

		extractedData, err := extractData(img)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Extraction error: %v", err))
			return
		}

		decryptedBytes, err := decrypt(extractedData, extractPassEntry.Text)
		if err != nil {
			statusLabel.SetText("Error: Decryption failed (Incorrect passphrase or invalid data).")
			dialog.ShowError(errors.New("Decryption failed! Wrong password or corrupted image data."), myWindow)
			return
		}

		extractedResultBox.SetText(string(decryptedBytes))
		statusLabel.SetText("Success! Message successfully extracted.")
	})

	extractContainer := container.NewVBox(
		widget.NewLabelWithStyle("Extract Secret Message from PNG", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Stego Image (PNG):"),
		container.NewBorder(nil, nil, nil, btnBrowseExtract, extractImgEntry),
		widget.NewLabel("Passphrase:"),
		extractPassEntry,
		widget.NewSeparator(),
		btnExtract,
		widget.NewLabel("Extracted Text:"),
		extractedScroll,
	)

	// Assemble Tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Hide", container.NewVScroll(hideContainer)),
		container.NewTabItem("Extract", container.NewVScroll(extractContainer)),
	)

	// Main Layout with status bar at the bottom
     mainLayout := container.NewBorder(nil, statusLabel, nil, nil, tabs)
	myWindow.SetContent(mainLayout)
	myWindow.ShowAndRun()
}
