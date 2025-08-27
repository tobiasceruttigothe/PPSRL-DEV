package org.paper.controllers;

import org.paper.services.ImageGenerationService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

@RestController
@RequestMapping("/api/ia")
public class IAController {

    private final ImageGenerationService service = new ImageGenerationService();

    // Recibe el prompt en el body
    @PostMapping(value = "/generar", consumes = MediaType.APPLICATION_JSON_VALUE)
    public String generarImagen(@RequestBody PromptRequest request) {
        String base64 = service.generarImagenBase64(request.getPrompt());
        if (base64 != null) {
            return base64;
        } else {
            return "Error al generar la imagen";
        }
    }

//    @GetMapping(value = "/mostrar", consumes = MediaType.APPLICATION_JSON_VALUE)
//    public String mostrarImagen(@RequestBody PromptRequest request) {
//        String base64 = service.consultarTask(request.getPrompt());
//        if (base64 != null) {
//            return base64;
//        } else {
//            return "Error al generar la imagen";
//        }
//    }
    @GetMapping(value = "/mostrar", consumes = MediaType.APPLICATION_JSON_VALUE)
    public String mostrarImagen(@RequestBody String request) {
        // request.getTaskId() debe contener el taskId recibido al generar la imagen
        String resultado = service.consultarTask(request);
        if (resultado != null) {
            return resultado;
        } else {
            return "Error al consultar la imagen";
        }
    }


}

// Clase auxiliar para mapear el JSON del prompt
class PromptRequest {
    private String prompt;

    public String getPrompt() { return prompt; }
    public void setPrompt(String prompt) { this.prompt = prompt; }
}
