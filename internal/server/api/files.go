package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/zyrak/zcloud/internal/server/middleware"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

const (
	// BaseFileDir directorio base para archivos (configurable)
	BaseFileDir = "/home/zcloud/files"
	// MaxUploadSize tamaño máximo de subida (100MB)
	MaxUploadSize = 100 << 20
)

// handleFileUpload procesa subidas de archivos multipart
func (a *API) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	// Limitar tamaño
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadSize)

	if err := r.ParseMultipartForm(MaxUploadSize); err != nil {
		a.jsonError(w, "file too large (max 100MB)", http.StatusBadRequest)
		return
	}

	// Obtener path destino
	destPath := r.FormValue("path")
	if destPath == "" {
		a.jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	// Sanitizar y validar path
	safePath, err := sanitizePath(destPath)
	if err != nil {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Obtener archivo
	file, header, err := r.FormFile("file")
	if err != nil {
		a.jsonError(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Decide whether "path" is a directory or a file path:
	// - If the client used a trailing slash (common UX for "upload into dir"), treat it as a directory.
	// - If the destination already exists and is a directory, treat it as a directory.
	destAbs := filepath.Join(BaseFileDir, safePath)
	destIsDir := safePath == "" || strings.HasSuffix(destPath, "/") || strings.HasSuffix(destPath, "\\")
	if !destIsDir {
		if info, err := os.Stat(destAbs); err == nil && info.IsDir() {
			destIsDir = true
		}
	}

	// Build the final target path.
	fullPath := destAbs
	respPath := safePath
	if destIsDir {
		filename, err := sanitizeUploadFilename(header.Filename)
		if err != nil {
			a.jsonError(w, "invalid filename", http.StatusBadRequest)
			return
		}
		fullPath = filepath.Join(destAbs, filename)
		respPath = filepath.Join(safePath, filename)
	} else if safePath == "" {
		// Uploading to "/" without a filename is ambiguous; require a directory path ("/") so we can
		// use the uploaded filename, or provide a full file path.
		a.jsonError(w, "path must include a filename (or end with a slash to upload into a directory)", http.StatusBadRequest)
		return
	}

	// Safety check: ensure the final target stays within BaseFileDir (defense-in-depth).
	cleanFullPath := filepath.Clean(fullPath)
	rel, err := filepath.Rel(BaseFileDir, cleanFullPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Crear directorio padre si no existe
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		a.jsonError(w, "failed to create directory", http.StatusInternalServerError)
		return
	}

	// Crear archivo destino
	dst, err := os.Create(fullPath)
	if err != nil {
		a.jsonError(w, "failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copiar contenido y calcular checksum
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(dst, hasher), file)
	if err != nil {
		os.Remove(fullPath)
		a.jsonError(w, "failed to write file", http.StatusInternalServerError)
		return
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("File uploaded by device %s: %s (%d bytes)", deviceID, fullPath, size)

	resp := &protocol.FileUploadResponse{
		Path:     respPath,
		Size:     size,
		Checksum: checksum,
		Message:  "File uploaded successfully",
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

// handleFileDownload stream de archivos
func (a *API) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	reqPath := r.URL.Query().Get("path")
	if reqPath == "" {
		a.jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	// Sanitizar path
	safePath, err := sanitizePath(reqPath)
	if err != nil {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	fullPath, err := resolvePathForRead(BaseFileDir, safePath)
	if err != nil {
		if os.IsNotExist(err) {
			a.jsonError(w, "file not found", http.StatusNotFound)
		} else {
			a.jsonError(w, "invalid path", http.StatusBadRequest)
		}
		return
	}

	// Verificar que existe y es archivo
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			a.jsonError(w, "file not found", http.StatusNotFound)
		} else {
			a.jsonError(w, "failed to access file", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() {
		a.jsonError(w, "path is a directory", http.StatusBadRequest)
		return
	}

	// Abrir archivo
	file, err := os.Open(fullPath)
	if err != nil {
		a.jsonError(w, "failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Configurar headers
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(fullPath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// Stream archivo
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("Error streaming file: %v", err)
		return
	}

	log.Printf("File downloaded by device %s: %s", deviceID, fullPath)
}

// handleFileList lista contenido de directorios
func (a *API) handleFileList(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Query().Get("path")
	if reqPath == "" {
		reqPath = "/"
	}

	recursive := r.URL.Query().Get("recursive") == "true"

	// Sanitizar path
	safePath, err := sanitizePath(reqPath)
	if err != nil {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	fullPath, err := resolvePathForRead(BaseFileDir, safePath)
	if err != nil {
		if os.IsNotExist(err) {
			a.jsonError(w, "path not found", http.StatusNotFound)
		} else {
			a.jsonError(w, "invalid path", http.StatusBadRequest)
		}
		return
	}

	// Verificar que existe
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			a.jsonError(w, "path not found", http.StatusNotFound)
		} else {
			a.jsonError(w, "failed to access path", http.StatusInternalServerError)
		}
		return
	}

	var files []protocol.FileInfo

	if info.IsDir() {
		if recursive {
			err = filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // Ignorar errores de acceso
				}
				relPath, _ := filepath.Rel(fullPath, path)
				if relPath == "." {
					return nil
				}
				files = append(files, protocol.FileInfo{
					Name:    info.Name(),
					Path:    filepath.Join(safePath, relPath),
					Size:    info.Size(),
					Mode:    info.Mode().String(),
					ModTime: info.ModTime(),
					IsDir:   info.IsDir(),
				})
				return nil
			})
		} else {
			entries, err := os.ReadDir(fullPath)
			if err != nil {
				a.jsonError(w, "failed to read directory", http.StatusInternalServerError)
				return
			}
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				files = append(files, protocol.FileInfo{
					Name:    info.Name(),
					Path:    filepath.Join(safePath, info.Name()),
					Size:    info.Size(),
					Mode:    info.Mode().String(),
					ModTime: info.ModTime(),
					IsDir:   info.IsDir(),
				})
			}
		}
	} else {
		// Es un archivo individual
		files = append(files, protocol.FileInfo{
			Name:    info.Name(),
			Path:    safePath,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
			IsDir:   false,
		})
	}

	resp := &protocol.FileListResponse{
		Files: files,
		Path:  safePath,
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

// handleFileDelete elimina un archivo o directorio
func (a *API) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	var req struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Path == "" || req.Path == "/" {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	safePath, err := sanitizePath(req.Path)
	if err != nil {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	// For deletion we do not resolve symlinks: removing a symlink removes the link itself (not the target),
	// and removing a directory tree does not follow symlinks. We still ensure the requested path is within
	// BaseFileDir to prevent traversal.
	fullPath, err := resolvePathForDelete(BaseFileDir, safePath)
	if err != nil {
		a.jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}

	// Use Lstat so symlinks are treated as symlinks (and not followed).
	info, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			a.jsonError(w, "file not found", http.StatusNotFound)
		} else {
			a.jsonError(w, "failed to access file", http.StatusInternalServerError)
		}
		return
	}

	if info.IsDir() && !req.Recursive {
		a.jsonError(w, "use recursive=true to delete directories", http.StatusBadRequest)
		return
	}

	if req.Recursive {
		err = os.RemoveAll(fullPath)
	} else {
		err = os.Remove(fullPath)
	}

	if err != nil {
		a.jsonError(w, "failed to delete", http.StatusInternalServerError)
		return
	}

	log.Printf("File deleted by device %s: %s", deviceID, fullPath)

	a.jsonResponse(w, map[string]string{"message": "File deleted"}, http.StatusOK)
}

// sanitizePath limpia y valida un path para prevenir path traversal
func sanitizePath(path string) (string, error) {
	// Limpiar path
	clean := filepath.Clean(path)
	clean = strings.TrimPrefix(clean, "/")

	// Verificar que no intenta escapar
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid path: contains ..")
	}

	return clean, nil
}

func sanitizeUploadFilename(name string) (string, error) {
	// Some clients may send Windows-style paths. Normalize, then take only the final base name.
	normalized := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	base := path.Base(normalized)
	base = strings.TrimSpace(base)

	// Reject empty / special / potentially confusing names.
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid filename")
	}

	// Defense-in-depth: ensure it doesn't contain any separators after normalization.
	if strings.Contains(base, "/") || strings.Contains(base, "\\") {
		return "", fmt.Errorf("invalid filename")
	}

	return base, nil
}

func resolvePathForRead(baseDir, safeRel string) (string, error) {
	abs, err := resolvePathForDelete(baseDir, safeRel)
	if err != nil {
		return "", err
	}

	// Resolve symlinks and ensure the final path still stays within the resolved base dir.
	resolvedTarget, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}

	baseResolved := filepath.Clean(baseDir)
	if br, err := filepath.EvalSymlinks(baseResolved); err == nil {
		baseResolved = br
	}

	resolvedTarget = filepath.Clean(resolvedTarget)
	rel, err := filepath.Rel(baseResolved, resolvedTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path: resolves outside base directory")
	}

	return resolvedTarget, nil
}

func resolvePathForDelete(baseDir, safeRel string) (string, error) {
	baseClean := filepath.Clean(baseDir)
	target := filepath.Clean(filepath.Join(baseClean, safeRel))

	rel, err := filepath.Rel(baseClean, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path: outside base directory")
	}

	return target, nil
}
