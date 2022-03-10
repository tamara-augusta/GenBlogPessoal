package org.generation.blogPessoal.service;

import java.nio.charset.Charset;
import java.util.Optional;

import org.apache.commons.codec.binary.Base64;

import org.generation.blogPessoal.model.UserLogin;
import org.generation.blogPessoal.model.Usuario;
import org.generation.blogPessoal.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {
	
	@Autowired
	private UsuarioRepository repository;
	
	public Optional<Usuario> CadastroUsuario (Usuario usuario) {
		if (repository.findByUsuario(usuario.getUsuario()).isPresent()) {
			return Optional.empty();
		}
		
		BCryptPasswordEncoder enconder = new BCryptPasswordEncoder();
		
		String senhaEncoder = enconder.encode(usuario.getSenha());
		usuario.setSenha(senhaEncoder);
		
		return Optional.ofNullable(repository.save(usuario));
	
	}
	
	public Optional<UserLogin> Logar(Optional<UserLogin> user){
		BCryptPasswordEncoder enconder = new BCryptPasswordEncoder();	
		Optional<Usuario> usuario = repository.findByUsuario(user.get().getUsuario());
		
		if (usuario.isPresent()) {
			if(enconder.matches(user.get().getSenha(), usuario.get().getSenha())) {
				
					String auth = user.get().getUsuario() + ":" + user.get().getSenha();
					byte[] encoderAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
					String authHearder ="Basic " + new String(encoderAuth);
					
					user.get().setToken(authHearder);
					user.get().setNome(usuario.get().getNome());
					
					return user;
			}
		}
		
		return null;
		
	}
	
}	
