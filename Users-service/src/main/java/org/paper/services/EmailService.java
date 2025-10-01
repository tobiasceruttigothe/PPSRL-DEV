package org.paper.services;


import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void enviarEmailVerificacion(String destinatario, String username, String token) {
        try {
            String verificationLink = frontendUrl + "/verify-email?token=" + token;

            log.info("Enviando email de verificación a {}", destinatario);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(destinatario);
            helper.setSubject("Verificación de email - Mi Aplicación");

            String htmlContent = """
                <html>
                <body>
                    <h2>Hola %s,</h2>
                    <p>Por favor verificá tu email haciendo clic en el siguiente botón:</p>
                    <p><a href="%s" style="background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verificar Email</a></p>
                    <p>O copiá este enlace en tu navegador: %s</p>
                    <p>Este enlace expira en 24 horas.</p>
                </body>
                </html>
            """.formatted(username, verificationLink, verificationLink);

            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.info("Email enviado a {}", destinatario);
        } catch (Exception e) {
            log.error("Error enviando email: {}", e.getMessage(), e);
            throw new RuntimeException("No se pudo enviar el email de verificación");
        }
    }
}
