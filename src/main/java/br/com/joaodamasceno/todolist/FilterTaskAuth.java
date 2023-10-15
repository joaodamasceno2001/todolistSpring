package br.com.joaodamasceno.todolist;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.joaodamasceno.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository iUserRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var serveletPath = request.getServletPath();

        if(serveletPath.startsWith("/tasks/")){
            //pegar autenticação (usuario e senha)
            var authorization  = request.getHeader("Authorization");


            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecode);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            //validar usuario
            var user = this.iUserRepository.findByUsername(username);
            if(user == null){
                response.sendError(401, "Usuario sem autorização");
            }else {
                //validar senha
                var passwordVerify =  BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if(passwordVerify.verified){
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                }else {
                    response.sendError(401);
                }
                //segue viagem


            }
        } else {
            filterChain.doFilter(request, response);
        }




    }
}
