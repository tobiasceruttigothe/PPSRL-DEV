package org.paper.services;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ImageGenerationService {

    private final String apiUrl = "https://api.kie.ai/api/v1/gpt4o-image/generate";
    private final String apiKey = "842f56ed8efeb9d37a788224acde8f69"; // Reemplaza con tu clave API

    private final String taskStatusUrl = "https://api.kie.ai/api/v1/image/tasks/";


    public String generarImagenBase64(String prompt) {
        try {
            String requestBody = String.format(
                    "{\"prompt\": \"%s\", \"outputFormat\": \"jpeg\", \"aspectRatio\": \"16:9\", \"model\": \"gpt-4o\"}",
                    prompt
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(apiKey);

            HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<String> response = restTemplate.exchange(
                    apiUrl,
                    HttpMethod.POST,
                    entity,
                    String.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                System.out.println("Respuesta completa: " + response.getBody());
                ObjectMapper mapper = new ObjectMapper();
                JsonNode root = mapper.readTree(response.getBody());
                JsonNode imagesNode = root.path("images");
                if (imagesNode.isArray() && imagesNode.size() > 0) {
                    return imagesNode.get(0).asText();
                } else {
                    System.err.println("No se generaron imágenes. Respuesta: " + response.getBody());
                }
            }
        } catch (Exception e) {
            System.err.println("Excepción al generar la imagen: " + e.getMessage());
        }
        return "a";
    }


    public String consultarTask(String taskId) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(apiKey);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<String> response = restTemplate.exchange(
                    taskStatusUrl + taskId, // Endpoint completo
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode root = mapper.readTree(response.getBody());
                System.out.println("Estado del task: " + root.toPrettyString());
                return root.toString(); // Puedes devolver lo que necesites (status, imágenes, etc.)
            }
        } catch (Exception e) {
            System.err.println("Excepción al consultar taskId: " + e.getMessage());
        }
        return null;
    }
}


