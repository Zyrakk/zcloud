package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// FilesClient cliente para transferencia de archivos
type FilesClient struct {
	config     *Config
	httpClient *http.Client
	baseURL    string
}

// NewFilesClient crea un nuevo cliente de archivos
func NewFilesClient(cfg *Config) *FilesClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Server.Insecure,
		},
	}

	return &FilesClient{
		config:  cfg,
		baseURL: cfg.Server.URL,
		httpClient: &http.Client{
			Timeout:   5 * time.Minute, // Más tiempo para transferencias
			Transport: transport,
		},
	}
}

// Upload sube un archivo local al servidor
func (f *FilesClient) Upload(localPath, remotePath string) (*protocol.FileUploadResponse, error) {
	// Abrir archivo local
	file, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Obtener info del archivo
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("cannot upload directory, use UploadDir")
	}

	// Crear buffer multipart
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Agregar campo path
	if err := writer.WriteField("path", remotePath); err != nil {
		return nil, fmt.Errorf("failed to write path field: %w", err)
	}

	// Agregar archivo
	part, err := writer.CreateFormFile("file", filepath.Base(localPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	// Calcular checksum mientras copiamos
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(part, hasher), file); err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	// Crear request
	req, err := http.NewRequest("POST", f.baseURL+"/api/v1/files/upload", &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	f.addAuthHeaders(req)

	// Enviar
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var errResp protocol.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("upload failed: %s", string(body))
	}

	var result protocol.FileUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UploadDir sube un directorio recursivamente
func (f *FilesClient) UploadDir(localDir, remoteDir string) ([]protocol.FileUploadResponse, error) {
	var results []protocol.FileUploadResponse

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Calcular path relativo
		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}

		// Path remoto
		remotePath := filepath.Join(remoteDir, relPath)
		remotePath = strings.ReplaceAll(remotePath, "\\", "/") // Normalizar para Linux

		fmt.Printf("  📤 %s -> %s\n", path, remotePath)

		result, err := f.Upload(path, remotePath)
		if err != nil {
			return fmt.Errorf("failed to upload %s: %w", path, err)
		}

		results = append(results, *result)
		return nil
	})

	return results, err
}

// Download descarga un archivo del servidor
func (f *FilesClient) Download(remotePath, localPath string) error {
	// Crear request
	req, err := http.NewRequest("GET", f.baseURL+"/api/v1/files/download?path="+url.QueryEscape(remotePath), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	f.addAuthHeaders(req)

	// Enviar
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var errResp protocol.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("download failed: %s", string(body))
	}

	// Determinar nombre del archivo
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		// localPath es un directorio, extraer nombre del archivo
		filename := filepath.Base(remotePath)
		localPath = filepath.Join(localPath, filename)
	}

	// Crear directorio si no existe
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Crear archivo local
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copiar contenido
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hasher), resp.Body)
	if err != nil {
		os.Remove(localPath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	fmt.Printf("  📥 Downloaded %d bytes (SHA256: %s)\n", size, safePrefix(checksum, 12))

	return nil
}

// List lista archivos en un directorio remoto
func (f *FilesClient) List(remotePath string, recursive bool) (*protocol.FileListResponse, error) {
	u := fmt.Sprintf("%s/api/v1/files/list?path=%s", f.baseURL, url.QueryEscape(remotePath))
	if recursive {
		u += "&recursive=true"
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	f.addAuthHeaders(req)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		var errResp protocol.ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("list failed: %s", string(body))
	}

	var result protocol.FileListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Delete elimina un archivo o directorio remoto
func (f *FilesClient) Delete(remotePath string, recursive bool) error {
	body := struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}{
		Path:      remotePath,
		Recursive: recursive,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", f.baseURL+"/api/v1/files/delete", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	f.addAuthHeaders(req)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp protocol.ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("delete failed: %s", string(respBody))
	}

	return nil
}

// addAuthHeaders agrega headers de autenticación
func (f *FilesClient) addAuthHeaders(req *http.Request) {
	if f.config.HasValidSession() {
		req.Header.Set("Authorization", "Bearer "+f.config.Session.Token)
	}
	if f.config.Device.ID != "" {
		req.Header.Set("X-Device-ID", f.config.Device.ID)
	}
}

// ParseRemotePath parsea un path en formato "remote:/path" o "local"
// Devuelve (isRemote, path)
func ParseRemotePath(path string) (bool, string) {
	if strings.HasPrefix(path, "remote:") {
		return true, strings.TrimPrefix(path, "remote:")
	}
	return false, path
}
