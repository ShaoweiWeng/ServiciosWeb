/**
 * ETSIINFLibrarySkeleton.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis2 version: 1.6.2  Built on : Apr 17, 2012 (05:33:49 IST)
 */
package es.upm.etsiinf.sos;

import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

import org.apache.axis2.AxisFault;

import es.upm.etsiinf.sos.model.xsd.Response;
import es.upm.etsiinf.sos.model.xsd.User;
import es.upm.etsiinf.sos.model.xsd.Book;
import es.upm.fi.sos.t3.backend.UPMAuthenticationAuthorizationWSSkeletonStub;

/**
 * ETSIINFLibrarySkeleton java skeleton for the axisService
 */
public class ETSIINFLibrarySkeleton {
	private UPMAuthenticationAuthorizationWSSkeletonStub serviceStub;

	private User userSession;

	private static Map<String, User> registeredUsers = new HashMap<>();
	private static Map<String, List<ETSIINFLibrarySkeleton>> activeUserSessions = new HashMap<>();

	private static final Logger logger = Logger.getLogger(ETSIINFLibrarySkeleton.class.getName());

	private static List<Book> books = new ArrayList<>();
	private static Map<String, Integer> ejemplares = new HashMap<>();
	private static Map<User, List<Book>> prestamos = new HashMap<>();

	private boolean hasBorrowedBooks(String userName) {
		for (Map.Entry<User, List<Book>> entries : prestamos.entrySet()) {
			User user = entries.getKey();
			List<Book> bookList = entries.getValue();
			if (user.getName().equals(userName) && !bookList.isEmpty()) {
				return true;
			}
		}
		return false;
	}

	public ETSIINFLibrarySkeleton() {
		userSession = null;
		try {
			serviceStub = new UPMAuthenticationAuthorizationWSSkeletonStub();
		} catch (AxisFault e) {
			e.printStackTrace();
		}
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param addUser
	 * @return addUserResponse
	 */

	public es.upm.etsiinf.sos.AddUserResponse addUser(es.upm.etsiinf.sos.AddUser addUser) {
		System.out.println("\n=== Start addUser ===");

		String userName = addUser.getArgs0().getUsername();
		System.out.println("Attempting to add user: " + userName);
		System.out.println("Current session user: " + (userSession != null ? userSession.getName() : "null"));
		System.out.println("Currently registered users: " + registeredUsers.keySet());

		AddUserResponse addUserResponse = new AddUserResponse();
		es.upm.etsiinf.sos.model.xsd.AddUserResponse response = new es.upm.etsiinf.sos.model.xsd.AddUserResponse();
		response.setResponse(false);

		if (userSession == null || !userSession.getName().equals("admin")) {
			System.out.println("ERROR: Only admin can add users. Current user: "
					+ (userSession != null ? userSession.getName() : "null"));
			addUserResponse.set_return(response);
			return addUserResponse;
		}

		if (registeredUsers.containsKey(userName)) {
			System.out.println("ERROR: User " + userName + " already exists");
			addUserResponse.set_return(response);
			return addUserResponse;
		}

		try {
			System.out.println("Preparing external service call...");

			UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd userBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd();
			userBackEnd.setName(userName);

			UPMAuthenticationAuthorizationWSSkeletonStub.AddUser addUserRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.AddUser();
			addUserRequest.setUser(userBackEnd);

			UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponse serviceResponse = serviceStub
					.addUser(addUserRequest);

			UPMAuthenticationAuthorizationWSSkeletonStub.AddUserResponseBackEnd backendResponse = serviceResponse
					.get_return();

			boolean result = backendResponse.getResult();
			System.out.println("External service result: " + result);
			response.setResponse(result);

			if (result) {
				String generatedPassword = backendResponse.getPassword();
				response.setPwd(generatedPassword);

				System.out.println("Generated password: " + generatedPassword);

				User newUser = new User();
				newUser.setName(userName);
				newUser.setPwd(generatedPassword);

				registeredUsers.put(userName, newUser);
				System.out.println("User added successfully: " + userName);
				System.out.println("Updated registered users: " + registeredUsers.keySet());
			} else {
				System.out.println("ERROR: External service failed to add user: " + userName);
				System.out.println("Possible reasons: ");
				System.out.println("- User already exists in external system");
				System.out.println("- External service unavailable");
				System.out.println("- Permission denied");
			}
		} catch (RemoteException e) {
			e.printStackTrace();

		}
		System.out.println("=== End addUser ===");
		addUserResponse.set_return(response);
		return addUserResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param login
	 * @return loginResponse
	 */

	public es.upm.etsiinf.sos.LoginResponse login(es.upm.etsiinf.sos.Login login) {
		System.out.println("\n=== Start login ===");

		User user = login.getArgs0();
		String loginUserName = login.getArgs0().getName();
		String loginUserPwd = login.getArgs0().getPwd();

		System.out.println("Attempting login for user: " + loginUserName);
		System.out.println("Current session user: " + (userSession != null ? userSession.getName() : "null"));
		System.out.println("Currently registered users: " + registeredUsers.keySet());

		LoginResponse loginResponse = new LoginResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userSession != null) {
			if (loginUserName.equals(userSession.getName())) {
				response.setResponse(true);
				System.out.println("User " + loginUserName + " is already logged in");
			} else {
				System.out.println(
						"A different user (" + loginUserName + ") is attempting to log in to the current session");
				System.out.println("Current session belongs to: " + userSession.getName());
				System.out.println("Please log out first to switch users");
				System.out.println("=== End login ===");
				response.setResponse(false);
				return loginResponse;
			}
		}

		if (loginUserName.equals("admin") && loginUserPwd.equals("admin")) {
			if (!registeredUsers.containsKey("admin")) {
				registeredUsers.put("admin", user);
				System.out.println("Admin added to local registry: " + loginUserName);
			}

			userSession = user;
			response.setResponse(true);

			if (!activeUserSessions.containsKey("admin")) {
				List<ETSIINFLibrarySkeleton> session = new ArrayList<>();
				session.add(this);
				activeUserSessions.put(loginUserName, session);
				System.out.println("New session created admin");
			} else {
				activeUserSessions.get(loginUserName).add(this);
				System.out.println("Added new session admin");
				System.out.println("Total sessions for admin: " + activeUserSessions.get("admin").size());
			}

			System.out.println("Admin logged in successfully");
		} else {
			try {
				System.out.println("Preparing external service call...");

				UPMAuthenticationAuthorizationWSSkeletonStub.LoginBackEnd loginBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.LoginBackEnd();
				loginBackEnd.setName(loginUserName);
				loginBackEnd.setPassword(loginUserPwd);

				UPMAuthenticationAuthorizationWSSkeletonStub.Login loginRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.Login();
				loginRequest.setLogin(loginBackEnd);

				UPMAuthenticationAuthorizationWSSkeletonStub.LoginResponse serviceResponse = serviceStub
						.login(loginRequest);

				UPMAuthenticationAuthorizationWSSkeletonStub.LoginResponseBackEnd backendResponse = serviceResponse
						.get_return();

				boolean result = backendResponse.getResult();
				response.setResponse(result);
				System.out.println("External service result: " + result);

				if (result) {
					if (!registeredUsers.containsKey(loginUserName)) {
						User loginUser = new User();
						loginUser.setName(loginUserName);
						loginUser.setPwd(loginUserPwd);
						registeredUsers.put(loginUserName, loginUser);
						System.out.println("User added to local registry: " + loginUserName);
					}

					userSession = registeredUsers.get(loginUserName);

					if (!activeUserSessions.containsKey(loginUserName)) {
						List<ETSIINFLibrarySkeleton> session = new ArrayList<>();
						session.add(this);
						activeUserSessions.put(loginUserName, session);
						System.out.println("New session created for user: " + loginUserName);
					} else {
						activeUserSessions.get(loginUserName).add(this);
						System.out.println("Added new session for user: " + loginUserName);
						System.out.println("Total sessions for user: " + activeUserSessions.get(loginUserName).size());
					}
					System.out.println("User " + loginUserName + " logged in successfully");
				} else {
					System.out.println("ERROR: Login failed for user: " + loginUserName);
				}
			} catch (RemoteException e) {
				e.printStackTrace();
			}
		}
		System.out.println("=== End login ===");
		loginResponse.set_return(response);
		return loginResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param logout
	 * @return logoutResponse
	 */

	public es.upm.etsiinf.sos.LogoutResponse logout(es.upm.etsiinf.sos.Logout logout) {
		System.out.println("\n=== Start logout ===");

		LogoutResponse logoutResponse = new LogoutResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userSession == null) {
			System.out.println("No user is currently logged in");
		} else {
			String userName = userSession.getName();
			System.out.println("Attempting to logout user: " + userName);
			System.out.println("Current active sessions: " + activeUserSessions.get(userName).size());

			if (activeUserSessions.containsKey(userName)) {
				int sessions = activeUserSessions.get(userName).size();
				System.out.println("Removing " + sessions + " session(s) for user: " + userName);

				activeUserSessions.remove(userName);
				response.setResponse(true);

				System.out.println("User " + userName + " logged out successfully");
				System.out.println("Removed sessions: " + sessions);
				System.out.println("Active sessions: " + activeUserSessions.keySet());
			} else {
				System.out.println("No active sessions found for user: " + userName);
			}
			userSession = null;
			System.out.println("User session cleared");
		}

		System.out.println("=== End logout ===");
		logoutResponse.set_return(response);
		return logoutResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param deleteUser
	 * @return deleteUserResponse
	 */

	public es.upm.etsiinf.sos.DeleteUserResponse deleteUser(es.upm.etsiinf.sos.DeleteUser deleteUser) {
		System.out.println("\n=== Start deleteUser ===");

		String userNameToDelete = deleteUser.getArgs0().getUsername();
		System.out.println("User to delete: " + userNameToDelete);

		System.out.println("User currently logged: " + userSession.getName());
		System.out.println("Registered users: " + registeredUsers.keySet());

		DeleteUserResponse deleteUserResponse = new DeleteUserResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userNameToDelete.equals("admin")) {
			System.out.println("Cannot delete admin user");
			deleteUserResponse.set_return(response);
			return deleteUserResponse;
		}

		if (hasBorrowedBooks(userNameToDelete)) {
			System.out.println("User: " + userNameToDelete + " has books borrowed");
			deleteUserResponse.set_return(response);
			return deleteUserResponse;
		}

		if (!userSession.getName().equals("admin") || !registeredUsers.containsKey(userNameToDelete)) {
			System.out.println(
					"Must be admin to delete this user / or user does not exist locally, must be registered first");
			deleteUserResponse.set_return(response);
			return deleteUserResponse;
		}

		try {
			UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd userBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.UserBackEnd();
			userBackEnd.setName(userNameToDelete);

			UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUser deleteUserRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUser();
			deleteUserRequest.setName(deleteUser.localArgs0.getUsername());
			deleteUserRequest.setPassword(registeredUsers.get(userNameToDelete).getPwd());

			UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserE deleteUserE = new UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserE();
			deleteUserE.setRemoveUser(deleteUserRequest);

			System.out.println("Preparing external service call...");
			UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserResponseE serviceResponse = serviceStub
					.removeUser(deleteUserE);

			UPMAuthenticationAuthorizationWSSkeletonStub.RemoveUserResponse backendResponse = serviceResponse
					.get_return();

			boolean result = backendResponse.getResult();
			System.out.println("External service result: " + result);
			response.setResponse(result);

			if (result) {
				System.out.println("Deleting user: " + userNameToDelete + " from local register");
				registeredUsers.remove(userNameToDelete);

				if (activeUserSessions.containsKey(userNameToDelete)) {
					System.out.println("Deleting " + userNameToDelete + "`s active sessions");
					activeUserSessions.remove(userNameToDelete);
				}
				System.out.println("User: " + userNameToDelete + " deleted");
				System.out.println("Registered users: " + registeredUsers.keySet());
			} else {
				System.out.println("ERROR: failed to delete user: " + userNameToDelete);
			}

		} catch (RemoteException e) {
			System.err.println("RemoteException occurred while deleting user");
			e.printStackTrace();
		}
		System.out.println("=== End deleteUser ===");
		deleteUserResponse.set_return(response);
		return deleteUserResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param changePassword
	 * @return changePasswordResponse
	 */

	public es.upm.etsiinf.sos.ChangePasswordResponse changePassword(es.upm.etsiinf.sos.ChangePassword changePassword) {
		System.out.println("\n=== Start changePassword ===");

		String oldPassword = changePassword.getArgs0().getOldpwd();
		String newPassword = changePassword.getArgs0().getNewpwd();

		System.out.println(
				"Attempting password change for user: " + (userSession != null ? userSession.getName() : "null"));
		System.out.println("Old password provided: " + (oldPassword != null ? "****" : "null"));
		System.out.println("New password provided: " + (newPassword != null ? "****" : "null"));

		ChangePasswordResponse changePwdResponse = new ChangePasswordResponse();
		Response response = new Response();
		response.setResponse(false);

		if (userSession == null) {
			System.out.println("No user is currently logged in");
			changePwdResponse.set_return(response);
			System.out.println("=== End changePassword ===");
			return changePwdResponse;
		}

		if (userSession.getName().equals("admin") && oldPassword.equals("admin")) {
			System.out.println("Processing admin password change...");
			userSession.setPwd(newPassword);
			response.setResponse(true);
			System.out.println("Admin password changed successfully");
		} else if (userSession.getPwd().equals(oldPassword)) {
			System.out.println("Processing user password change...");
			try {
				System.out.println("Preparing external service call...");

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordBackEnd changePwdBackEnd = new UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordBackEnd();
				changePwdBackEnd.setOldpwd(oldPassword);
				changePwdBackEnd.setNewpwd(newPassword);
				changePwdBackEnd.setName(userSession.getName());

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePassword changePwdRequest = new UPMAuthenticationAuthorizationWSSkeletonStub.ChangePassword();
				changePwdRequest.setChangePassword(changePwdBackEnd);

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordResponseE serviceResponse = serviceStub
						.changePassword(changePwdRequest);

				UPMAuthenticationAuthorizationWSSkeletonStub.ChangePasswordResponse backendResponse = serviceResponse
						.get_return();

				boolean result = backendResponse.getResult();
				System.out.println("External service result: " + result);
				response.setResponse(result);

				if (result) {
					userSession.setPwd(newPassword);
					System.out.println("Password changed for user: " + userSession.getName());
					System.out.println("Local session password updated");
				} else {
					System.out.println("ERROR: Password change failed for user: " + userSession.getName());
					System.out.println("Possible reasons:");
					System.out.println("- External service rejected the change");
					System.out.println("- Password doesn't meet requirements");
					System.out.println("- Network or service error");
				}
			} catch (RemoteException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("ERROR: Password change failed");
			System.out.println("Possible reasons:");
			System.out.println("- Old password doesn't match");
			System.out.println("- No valid session");
			System.out.println("- User not authorized");
		}

		System.out.println("=== End changePassword ===");
		changePwdResponse.set_return(response);
		return changePwdResponse;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param borrowBook
	 * @return borrowBookResponse
	 */

	public es.upm.etsiinf.sos.BorrowBookResponse borrowBook(es.upm.etsiinf.sos.BorrowBook borrowBook) {
		es.upm.etsiinf.sos.BorrowBookResponse response = new es.upm.etsiinf.sos.BorrowBookResponse();
		es.upm.etsiinf.sos.model.xsd.Response result = new es.upm.etsiinf.sos.model.xsd.Response();

		if (userSession == null) {
			logger.info("borrowBook: usuario no autenticado");
			result.setResponse(false);
			response.set_return(result);
			return response;
		}

		String isbn = borrowBook.getArgs0();
		logger.info("borrowBook: usuario autenticado - " + userSession.getName() + " solicita ISBN: " + isbn);

		Book libroEncontrado = null;
		for (Book libro : books) {
			if (libro.getISSN().equalsIgnoreCase(isbn)) {
				libroEncontrado = libro;
				break;
			}
		}

		if (libroEncontrado == null) {
			logger.info("borrowBook: libro no encontrado con ISBN " + isbn);
			result.setResponse(false);
			response.set_return(result);
			return response;
		}

		if (!ejemplares.containsKey(isbn) || ejemplares.get(isbn) <= 0) {
			logger.info("borrowBook: no hay ejemplares disponibles para el ISBN " + isbn);
			result.setResponse(false);
			response.set_return(result);
			return response;
		}

		List<Book> librosPrestados = prestamos.getOrDefault(userSession, new ArrayList<>());
		for (Book prestado : librosPrestados) {
			if (prestado.getISSN().equalsIgnoreCase(isbn)) {
				logger.info("borrowBook: el usuario ya tiene prestado el libro con ISBN " + isbn);
				result.setResponse(false);
				response.set_return(result);
				return response;
			}
		}

		librosPrestados.add(libroEncontrado);
		prestamos.put(userSession, librosPrestados);

		int disponibles = ejemplares.get(isbn);
		ejemplares.put(isbn, disponibles - 1);

		logger.info("borrowBook: préstamo realizado correctamente. Ejemplares restantes: " + (disponibles - 1));

		result.setResponse(true);
		response.set_return(result);
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param returnBook
	 * @return returnBookResponse
	 */

	public es.upm.etsiinf.sos.ReturnBookResponse returnBook(es.upm.etsiinf.sos.ReturnBook returnBook) {
		es.upm.etsiinf.sos.ReturnBookResponse response = new es.upm.etsiinf.sos.ReturnBookResponse();
		es.upm.etsiinf.sos.model.xsd.Response result = new es.upm.etsiinf.sos.model.xsd.Response();
		result.setResponse(false);

		if (userSession == null) {
			logger.info("returnBook: usuario no autenticado");
			response.set_return(result);
			return response;
		}

		String isbn = returnBook.getArgs0();
		logger.info("returnBook: solicitando devolución de ISBN " + isbn + " por usuario " + userSession.getName());

		List<Book> librosPrestados = prestamos.get(userSession);
		if (librosPrestados != null) {
			Iterator<Book> it = librosPrestados.iterator();
			while (it.hasNext()) {
				Book libro = it.next();
				if (libro.getISSN().equalsIgnoreCase(isbn)) {
					it.remove();
					if (ejemplares.containsKey(isbn)) {
						int disponibles = ejemplares.get(isbn);
						ejemplares.put(isbn, disponibles + 1);
					} else {
						ejemplares.put(isbn, 1);
					}
					prestamos.put(userSession, librosPrestados);
					logger.info("returnBook: libro devuelto con éxito");
					result.setResponse(true);
					break;
				}
			}
		}
		if (!result.getResponse()) {
			logger.info("returnBook: el libro no estaba en la lista de préstamos del usuario");
		}
		response.set_return(result);
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param removeBook
	 * @return removeBookResponse
	 */

	public es.upm.etsiinf.sos.RemoveBookResponse removeBook(es.upm.etsiinf.sos.RemoveBook removeBook) {
		es.upm.etsiinf.sos.RemoveBookResponse response = new es.upm.etsiinf.sos.RemoveBookResponse();
		es.upm.etsiinf.sos.model.xsd.Response responseAttr = new es.upm.etsiinf.sos.model.xsd.Response();
		responseAttr.setResponse(false);

		// Solo admin puede eliminar libros
		if (userSession == null || !userSession.getName().equals("admin")) {
			logger.info("Acceso denegado: solo el usuario admin puede eliminar libros");
			response.set_return(responseAttr);
			return response;
		}

		String issn = removeBook.getArgs0();
		if (issn == null || issn.trim().isEmpty()) {
			logger.info("ISSN inválido");
			response.set_return(responseAttr);
			return response;
		}

		synchronized (books) {
			for (int i = 0; i < books.size(); i++) {
				Book book = books.get(i);
				if (issn.equals(book.getISSN())) {
					boolean prestado = false;
					for (List<Book> librosPrestados : prestamos.values()) {
						if (librosPrestados != null && librosPrestados.contains(book)) {
							prestado = true;
							break;
						}
					}
					if (prestado) {
						logger.info("No se puede eliminar el libro: está prestado");
						response.set_return(responseAttr);
						return response;
					}
					int numEjemplares = ejemplares.getOrDefault(issn, 0);
					if (numEjemplares > 1) {
						ejemplares.put(issn, numEjemplares - 1);
						logger.info(
								"Ejemplar eliminado, quedan " + (numEjemplares - 1) + " ejemplares de ISSN: " + issn);
					} else {
						ejemplares.remove(issn);
						books.remove(i);
						logger.info("Último ejemplar eliminado, libro borrado de la biblioteca: ISSN " + issn);
					}
					responseAttr.setResponse(true);
					response.set_return(responseAttr);
					return response;
				}
			}
		}
		logger.info("No se encontró ejemplar con ISSN: " + issn + " o está prestado");
		response.set_return(responseAttr);
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param getBook
	 * @return getBookResponse
	 */

	public es.upm.etsiinf.sos.GetBookResponse getBook(es.upm.etsiinf.sos.GetBook getBook) {
		es.upm.etsiinf.sos.GetBookResponse response = new es.upm.etsiinf.sos.GetBookResponse();
		es.upm.etsiinf.sos.model.xsd.Book bookResult = new es.upm.etsiinf.sos.model.xsd.Book();

		// Verificar que hay un usuario autenticado
		if (userSession == null) {
			logger.info("No hay usuario autenticado para getBook");
			response.set_return(bookResult); // Devuelve objeto vacío
			return response;
		}

		String issn = getBook.getArgs0();
		if (issn == null || issn.trim().isEmpty()) {
			logger.info("ISSN no proporcionado o vacío en getBook");
			response.set_return(bookResult); // Devuelve objeto vacío
			return response;
		}

		// Buscar el libro por ISSN
		synchronized (books) {
			for (Book b : books) {
				if (issn.equals(b.getISSN())) {
					response.set_return(b);
					return response;
				}
			}
		}
		// Si no se encuentra, devuelve objeto vacío
		logger.info("No se encontró libro con ISSN: " + issn);
		response.set_return(bookResult);
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param listBooks
	 * @return listBooksResponse
	 */

	public es.upm.etsiinf.sos.ListBooksResponse listBooks(es.upm.etsiinf.sos.ListBooks listBooks) {
		es.upm.etsiinf.sos.ListBooksResponse response = new es.upm.etsiinf.sos.ListBooksResponse();
		es.upm.etsiinf.sos.model.xsd.BookList bookList = new es.upm.etsiinf.sos.model.xsd.BookList();

		if (userSession == null) {
			bookList.setResult(false);
			bookList.setBookNames(new String[0]);
			bookList.setIssns(new String[0]);
			response.set_return(bookList);
			logger.info("listBooks: usuario no autenticado");
			return response;
		}

		bookList.setResult(true);
		int n = books.size();
		String[] bookNames = new String[n];
		String[] issns = new String[n];

		for (int i = 0; i < n; i++) {
			Book b = books.get(n - 1 - i);
			bookNames[i] = b.getName();
			issns[i] = b.getISSN();
		}

		bookList.setBookNames(bookNames);
		bookList.setIssns(issns);
		response.set_return(bookList);
		logger.info("listBooks: devueltos " + n + " libros");
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param addBook
	 * @return addBookResponse
	 */

	public es.upm.etsiinf.sos.AddBookResponse addBook(es.upm.etsiinf.sos.AddBook addBook) {
		es.upm.etsiinf.sos.AddBookResponse response = new es.upm.etsiinf.sos.AddBookResponse();
		es.upm.etsiinf.sos.model.xsd.Response responseAttr = new es.upm.etsiinf.sos.model.xsd.Response();
		responseAttr.setResponse(false);

		if (userSession == null || !userSession.getName().equals("admin")) {
			logger.info("Acceso denegado: solo el usuario admin puede añadir libros");
			response.set_return(responseAttr);
			return response;
		}

		Book book = addBook.getArgs0();
		if (book == null) {
			logger.info("Libro nulo");
			response.set_return(responseAttr);
			return response;
		}

		String name = book.getName();
		String issn = book.getISSN();
		String[] authors = book.getAuthors();

		boolean valid = name != null && !name.trim().isEmpty() && issn != null && !issn.trim().isEmpty()
				&& authors != null && authors.length > 0;
		if (!valid) {
			logger.info("Libro inválido: faltan campos obligatorios");
			response.set_return(responseAttr);
			return response;
		}

		synchronized (books) {
			boolean existe = false;
			for (Book b : books) {
				if (issn.equals(b.getISSN())) {
					existe = true;
					break;
				}
			}
			if (existe) {
				ejemplares.put(issn, ejemplares.get(issn) + 1);
				logger.info("Ejemplar añadido a libro existente: " + name + " (ISSN: " + issn + ")");
			} else {
				books.add(book);
				ejemplares.put(issn, 1);
				logger.info("Libro añadido correctamente: " + name + " (ISSN: " + issn + ")");
			}
		}
		responseAttr.setResponse(true);
		response.set_return(responseAttr);
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param getBooksFromAuthor
	 * @return getBooksFromAuthorResponse
	 */

	public es.upm.etsiinf.sos.GetBooksFromAuthorResponse getBooksFromAuthor(
			es.upm.etsiinf.sos.GetBooksFromAuthor getBooksFromAuthor) {
		es.upm.etsiinf.sos.GetBooksFromAuthorResponse response = new es.upm.etsiinf.sos.GetBooksFromAuthorResponse();
		es.upm.etsiinf.sos.model.xsd.BookList bookList = new es.upm.etsiinf.sos.model.xsd.BookList();

		if (userSession == null) {
			bookList.setResult(false);
			bookList.setBookNames(new String[0]);
			bookList.setIssns(new String[0]);
			response.set_return(bookList);
			logger.info("getBooksFromAuthor: usuario no autenticado");
			return response;
		}

		String authorName = getBooksFromAuthor.getArgs0().getName();
		logger.info("getBooksFromAuthor: buscando libros del autor \"" + authorName + "\"");

		List<Book> librosAutor = new ArrayList<>();
		for (Book libro : books) {
			String[] autores = libro.getAuthors();
			if (autores != null) {
				for (String autor : autores) {
					if (autor != null && autor.equalsIgnoreCase(authorName)) {
						librosAutor.add(libro);
						break;
					}
				}
			}
		}

		int n = librosAutor.size();
		String[] bookNames = new String[n];
		String[] issns = new String[n];

		for (int i = 0; i < n; i++) {
			Book b = librosAutor.get(n - 1 - i);
			bookNames[i] = b.getName();
			issns[i] = b.getISSN();
		}

		bookList.setResult(true);
		bookList.setBookNames(bookNames);
		bookList.setIssns(issns);
		response.set_return(bookList);
		logger.info("getBooksFromAuthor: devueltos " + n + " libros del autor \"" + authorName + "\"");
		return response;
	}

	/**
	 * Auto generated method signature
	 * 
	 * @param listBorrowedBooks
	 * @return listBorrowedBooksResponse
	 */

	public es.upm.etsiinf.sos.ListBorrowedBooksResponse listBorrowedBooks(
			es.upm.etsiinf.sos.ListBorrowedBooks listBorrowedBooks) {
		es.upm.etsiinf.sos.ListBorrowedBooksResponse response = new es.upm.etsiinf.sos.ListBorrowedBooksResponse();
		es.upm.etsiinf.sos.model.xsd.BookList bookList = new es.upm.etsiinf.sos.model.xsd.BookList();

		if (userSession == null) {
			bookList.setResult(false);
			bookList.setBookNames(new String[0]);
			bookList.setIssns(new String[0]);
			response.set_return(bookList);
			logger.info("listBorrowedBooks: usuario no autenticado");
			return response;
		}

		List<Book> librosPrestados = prestamos.getOrDefault(userSession, new ArrayList<>());

		int n = librosPrestados.size();
		String[] bookNames = new String[n];
		String[] issns = new String[n];

		for (int i = 0; i < n; i++) {
			Book b = librosPrestados.get(n - 1 - i);
			bookNames[i] = b.getName();
			issns[i] = b.getISSN();
		}

		bookList.setResult(true);
		bookList.setBookNames(bookNames);
		bookList.setIssns(issns);
		response.set_return(bookList);

		logger.info("listBorrowedBooks: devueltos " + n + " libros prestados para el usuario " + userSession.getName());
		return response;
	}

}