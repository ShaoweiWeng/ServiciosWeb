package es.upm.etsiinf.sos;

import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddUserResponseE;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Book;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePassword;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ChangePasswordResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUser;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.DeleteUserResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Login;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.LoginResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Logout;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.PasswordPair;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.User;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.Username;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.AddBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.RemoveBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.GetBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBooks;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBooksResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.GetBooksFromAuthor;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.GetBooksFromAuthorResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBorrowedBooks;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ListBorrowedBooksResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.BorrowBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.BorrowBookResponse;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ReturnBook;
import es.upm.etsiinf.sos.ETSIINFLibraryStub.ReturnBookResponse;

import java.rmi.RemoteException;

public class ClientETSIINFLibrary {
	private static ETSIINFLibraryStub stub;

	public static void main(String[] args) throws Exception {
		stub = new ETSIINFLibraryStub();
		stub._getServiceClient().getOptions().setManageSession(true);
		stub._getServiceClient().engageModule("addressing");

		loginAsAdmin();
		logout();

		loginAsUser("yujie.weng", "yujie.weng1234");
		loginAsUser("yujie.weng", "yujie.weng1234");
		logout();

		loginAsAdmin();
		addNewUser("changePasswordTest");
		addNewUser("deleteUserTest");
		deleteUser("deleteUserTest");
		logout();

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		changePassword("changePasswordTestNewPassword", "changePasswordTestNewPassword");
		logout();

		testAddBook();
		testRemoveBook();
		testGetBook();
		testListBooks();

		testGetFromAuthor();
		testBorrowBook();
		System.out.println(
				"--- Listar libros prestados del usuario changePasswordTest después del borrow para ver que se prestó el libro ---");
		testListBorrowedBooks();
		testReturnBook();
		System.out.println(
				"--- Listar libros prestados del usuario changePasswordTest después del return para ver que ya no está el libro ---");
		testListBorrowedBooks();
	}

	private static void loginAsAdmin() throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName("admin");
		user.setPwd("admin");
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("Admin login successful");
			} else {
				System.out.println("Admin login failed");
			}
		} catch (RemoteException e) {
			System.out.println("Error: " + e.getMessage());
		}
	}

	private static void addNewUser(String userName) throws RemoteException {
		AddUser addUser = new AddUser();
		Username user = new Username();
		user.setUsername(userName);
		addUser.setArgs0(user);

		try {
			AddUserResponseE addUserResponse = stub.addUser(addUser);
			if (addUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " added successfully");
				System.out.println("Password: " + addUserResponse.get_return().getPwd());
			} else {
				System.out.println("Adding user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void loginAsUser(String userName, String password) throws RemoteException {
		Login login = new Login();
		User user = new User();
		user.setName(userName);
		user.setPwd(password);
		login.setArgs0(user);

		try {
			LoginResponse loginResponse = stub.login(login);
			if (loginResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " logged in successfully");
			} else {
				System.out.println("User login failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void logout() throws RemoteException {
		try {
			Logout logout = new Logout();
			stub.logout(logout);
			System.out.println("Logout successful");
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void deleteUser(String userName) throws RemoteException {
		DeleteUser deleteUser = new DeleteUser();
		Username user = new Username();
		user.setUsername(userName);
		deleteUser.setArgs0(user);

		try {
			DeleteUserResponse deleteUserResponse = stub.deleteUser(deleteUser);
			if (deleteUserResponse.get_return().getResponse()) {
				System.out.println("User: " + userName + " deleted successfully");
			} else {
				System.out.println("Deleting user failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void changePassword(String oldPassword, String newPassword) throws RemoteException {
		ChangePassword changePassword = new ChangePassword();
		PasswordPair passwordPair = new PasswordPair();
		passwordPair.setOldpwd(oldPassword);
		passwordPair.setNewpwd(newPassword);
		changePassword.setArgs0(passwordPair);

		try {
			ChangePasswordResponse response = stub.changePassword(changePassword);
			if (response.get_return().getResponse()) {
				System.out.println("Password changed successfully");
			} else {
				System.out.println("Changing password failed");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	private static void testAddBook() throws RemoteException {
		System.out.println("\n--- testAddBook ---");
		// 1. Añadir libro como admin
		System.out.println("---AddBook exitoso como admin---");
		loginAsAdmin();
		Book book = new Book();
		book.setName("LibroTest");
		book.setISSN("1234567890");
		book.setAuthors(new String[] { "Autor1", "Autor2" });
		AddBook addBook = new AddBook();
		addBook.setArgs0(book);
		boolean added = stub.addBook(addBook).get_return().getResponse();
		System.out.println("Admin añade libro: " + (added ? "OK" : "FAIL"));
		logout();

		// 2. Añadir libro como usuario no admin
		System.out.println("---AddBook como usuario no admin, debe fallar---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		AddBook addBook2 = new AddBook();
		Book book2 = new Book();
		book2.setName("LibroTest2");
		book2.setISSN("0987654321");
		book2.setAuthors(new String[] { "Autor3" });
		addBook2.setArgs0(book2);
		boolean added2 = stub.addBook(addBook2).get_return().getResponse();
		System.out.println("Usuario no admin añade libro: " + (added2 ? "OK" : "FAIL"));
		logout();

		// 3. Añadir libro con datos incompletos
		System.out.println("---AddBook con datos incompletos, debe fallar---");
		loginAsAdmin();
		AddBook addBook3 = new AddBook();
		Book book3 = new Book();
		book3.setName(""); // nombre vacío
		book3.setISSN(""); // ISSN vacío
		book3.setAuthors(new String[] {}); // autores vacío
		addBook3.setArgs0(book3);
		boolean added3 = stub.addBook(addBook3).get_return().getResponse();
		System.out.println("Admin añade libro con datos incompletos: " + (added3 ? "OK" : "FAIL"));

		// 4. Añadir libro que ya existe
		System.out.println("---AddBook duplicado, exitoso debe añadir ejemplar---");
		Book book4 = new Book();
		book4.setName("LibroTest");
		book4.setISSN("1234567890");
		book4.setAuthors(new String[] { "Autor1", "Autor2" });
		AddBook addBook4 = new AddBook();
		addBook4.setArgs0(book4);
		boolean added4 = stub.addBook(addBook4).get_return().getResponse();
		System.out.println("Admin añade libro duplicado: " + (added4 ? "OK" : "FAIL"));
		logout();
	}

	private static void testRemoveBook() throws RemoteException {
		System.out.println("\n--- testRemoveBook ---");
		// 1. Eliminar libro como admin
		System.out.println("---RemoveBook exitoso como admin---");
		loginAsAdmin();
		RemoveBook removeBook = new RemoveBook();
		removeBook.setArgs0("1234567890");
		boolean removed = stub.removeBook(removeBook).get_return().getResponse();
		System.out.println("Admin elimina libro: " + (removed ? "OK" : "FAIL"));
		logout();

		// 2. Eliminar libro como usuario no admin
		System.out.println("---RemoveBook como usuario no admin, debe fallar---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		RemoveBook removeBook2 = new RemoveBook();
		removeBook2.setArgs0("0987654321");
		boolean removed2 = stub.removeBook(removeBook2).get_return().getResponse();
		System.out.println("Usuario no admin elimina libro: " + (removed2 ? "OK" : "FAIL"));
		logout();

		// 3. Eliminar libro que no existe
		System.out.println("---RemoveBook de libro inexistente, debe fallar---");
		loginAsAdmin();
		RemoveBook removeBook3 = new RemoveBook();
		removeBook3.setArgs0("noexiste");
		boolean removed3 = stub.removeBook(removeBook3).get_return().getResponse();
		System.out.println("Admin elimina libro inexistente: " + (removed3 ? "OK" : "FAIL"));
		logout();
	}

	private static void testGetBook() throws RemoteException {
		System.out.println("\n--- testGetBook ---");
		// 1. Obtener libro existente
		System.out.println("---GetBook existente---");
		loginAsAdmin();
		AddBook addBook = new AddBook();
		Book book = new Book();
		book.setName("LibroGet");
		book.setISSN("1111111111");
		book.setAuthors(new String[] { "AutorGet1", "AutorGet2", "AutorGet3" });
		addBook.setArgs0(book);
		stub.addBook(addBook);
		GetBook getBook = new GetBook();
		getBook.setArgs0("1111111111");
		Book result = stub.getBook(getBook).get_return();
		System.out.println("Nombre: " + result.getName());
		System.out.println("ISSN: " + result.getISSN());
		System.out.print("Autores: ");
		if (result.getAuthors() != null && result.getAuthors().length > 0) {
			for (int i = 0; i < result.getAuthors().length; i++) {
				System.out.print(result.getAuthors()[i]);
				if (i < result.getAuthors().length - 1) {
					System.out.print(", ");
				}
			}
			System.out.println();
		} else {
			System.out.println("null");
		}

		// 2. Obtener libro inexistente
		GetBook getBook2 = new GetBook();
		getBook2.setArgs0("noexiste");
		Book result2 = stub.getBook(getBook2).get_return();
		System.out.println(
				"---GetBook inexistente---\n"
						+ "Nombre: " + (result2 != null && result2.getName() != null ? result2.getName() : "null")
						+ "\n"
						+ "ISSN: " + (result2 != null && result2.getISSN() != null ? result2.getISSN() : "null") + "\n"
						+ "Autores: "
						+ (result2 != null && result2.getAuthors() != null && result2.getAuthors()[0] != null
								? result2.getAuthors()[0]
								: "null"));
		logout();

		// 3. Obtener libro sin autenticación
		GetBook getBook3 = new GetBook();
		getBook3.setArgs0("1111111111");
		Book result3 = stub.getBook(getBook3).get_return();
		System.out.println("---GetBook sin autenticación---\n"
				+ "Nombre: " + (result3 != null && result3.getName() != null ? result3.getName() : "null") + "\n"
				+ "ISSN: " + (result3 != null && result3.getISSN() != null ? result3.getISSN() : "null") + "\n"
				+ "Autores: "
				+ (result3 != null && result3.getAuthors() != null && result3.getAuthors()[0] != null
						? result3.getAuthors()[0]
						: "null"));
	}

	private static void testListBooks() throws RemoteException {
		System.out.println("\n--- testListBooks ---");
		// 1. Listar libros autenticado
		System.out.println("---ListBooks autenticado---");
		loginAsAdmin();
		ListBooks listBooks = new ListBooks();
		ListBooksResponse response = stub.listBooks(listBooks);
		String[] books = response.get_return().getBookNames();
		for (String libro : books) {
			System.out.println("Libro:" + libro + "\n");
		}
		logout();

		// 2. Listar libros sin autenticación
		System.out.println("---ListBooks sin autenticación---");
		ListBooks listBooks2 = new ListBooks();
		ListBooksResponse response2 = stub.listBooks(listBooks2);
		String[] books2 = response2.get_return().getBookNames();
		System.out.println(books2);
	}

	private static void testGetFromAuthor() throws RemoteException {
		System.out.println("\n--- testGetFromAuthor ---");
		loginAsAdmin();
		System.out.println("\n--- Caso 1: Caso exito con autor existente ---");
		// Añadir un libro de un autor específico
		Book book = new Book();
		book.setName("LibroAutor");
		book.setISSN("2222222222");
		book.setAuthors(new String[] { "AutorEjemplo" });
		AddBook addBook = new AddBook();
		addBook.setArgs0(book);
		stub.addBook(addBook);

		// Añadir otro libro para el mismo autor
		Book book2 = new Book();
		book2.setName("LibroAutor2");
		book2.setISSN("2222222223");
		book2.setAuthors(new String[] { "AutorEjemplo" });
		AddBook addBook2 = new AddBook();
		addBook2.setArgs0(book2);
		stub.addBook(addBook2);

		GetBooksFromAuthor get = new GetBooksFromAuthor();
		ETSIINFLibraryStub.Author author = new ETSIINFLibraryStub.Author();
		author.setName("AutorEjemplo");
		get.setArgs0(author);

		String[] books = stub.getBooksFromAuthor(get).get_return().getBookNames();
		System.out.println("Libros de 'AutorEjemplo':");
		for (String b : books) {
			System.out.println("- " + b);
		}

		// 2. Autor inexistente
		System.out.println("\n--- Caso 2: Autor inexistente ---");
		GetBooksFromAuthor req2 = new GetBooksFromAuthor();
		ETSIINFLibraryStub.Author author2 = new ETSIINFLibraryStub.Author();
		author2.setName("AutorNoExiste");
		req2.setArgs0(author2);
		String[] result2 = stub.getBooksFromAuthor(req2).get_return().getBookNames();
		if (result2 == null) {
			System.out.println("Correcto: No hay libros para el autor inexistente.");
		} else {
			System.out.println("Error: Se devolvieron libros para un autor que no existe.");
		}

		// 3. autor como segundo en la lista
		System.out.println("\n--- Caso 3: Autor como coautor ---");
		Book book3 = new Book();
		book3.setName("LibroCoautor");
		book3.setISSN("2222222223");
		book3.setAuthors(new String[] { "AutorPrincipal", "CoAutor" });
		AddBook addBook3 = new AddBook();
		addBook3.setArgs0(book3);
		stub.addBook(addBook3);

		GetBooksFromAuthor req3 = new GetBooksFromAuthor();
		ETSIINFLibraryStub.Author author3 = new ETSIINFLibraryStub.Author();
		author3.setName("CoAutor");
		req3.setArgs0(author3);
		String[] result3 = stub.getBooksFromAuthor(req3).get_return().getBookNames();

		System.out.println("Libros encontrados para CoAutor:");
		for (String name : result3) {
			System.out.println("- " + name);
		}
		logout();
		
		// 4. Intento sin autenticación
		System.out.println("\n--- Caso 5: Sin autenticación ---");
		GetBooksFromAuthor req5 = new GetBooksFromAuthor();
		ETSIINFLibraryStub.Author author5 = new ETSIINFLibraryStub.Author();
		author5.setName("AutorMultiple");
		req5.setArgs0(author5);
		String[] result5 = stub.getBooksFromAuthor(req5).get_return().getBookNames();

		if (result5.length == 0) {
			System.out.println("Correcto: No se devolvieron libros al no estar autenticado.");
		} else {
			System.out.println("Error: Se devolvieron libros sin autenticación.");
		}
	}

	private static void testBorrowBook() throws RemoteException {
		System.out.println("\n--- testBorrowBook ---");

		// 1. Préstamo correcto
		System.out.println("--- Caso 1: Préstamo correcto ---");
		loginAsAdmin();
		System.out.println("- Añadiendo un nuevo libro para realizar préstamo -");
		Book book = new Book();
		book.setName("LibroPrestamo1");
		book.setISSN("3333333331");
		book.setAuthors(new String[] { "Autor1" });
		AddBook addBook = new AddBook();
		addBook.setArgs0(book);
		stub.addBook(addBook);
		logout();

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");

		BorrowBook borrow = new BorrowBook();
		borrow.setArgs0("3333333331");
		boolean borrowed = stub.borrowBook(borrow).get_return().getResponse();
		System.out.println("Préstamo realizado: " + (borrowed ? "OK" : "FAIL"));
		logout();

		// 2. Libro no existe
		System.out.println("\n--- Caso 2: Préstamo de libro inexistente ---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");

		BorrowBook borrow2 = new BorrowBook();
		borrow2.setArgs0("9999999999"); // ISSN inexistente
		boolean borrowed2 = stub.borrowBook(borrow2).get_return().getResponse();
		System.out.println("Préstamo de libro inexistente: " + (borrowed2 ? "OK" : "FAIL"));
		logout();

		// 3. Usuario ya ha tomado el libro
		System.out.println("\n--- Caso 3: Préstamo repetido por mismo usuario ---");
		loginAsAdmin();
		Book book3 = new Book();
		book3.setName("LibroPrestamo2");
		book3.setISSN("3333333332");
		book3.setAuthors(new String[] { "Autor2" });
		AddBook addBook3 = new AddBook();
		addBook3.setArgs0(book3);
		stub.addBook(addBook3);
		logout();

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		BorrowBook borrow3 = new BorrowBook();
		borrow3.setArgs0("3333333332");
		boolean firstAttempt = stub.borrowBook(borrow3).get_return().getResponse();
		boolean secondAttempt = stub.borrowBook(borrow3).get_return().getResponse();
		System.out.println("Primer préstamo: " + (firstAttempt ? "OK" : "FAIL"));
		System.out.println("Segundo préstamo (debería fallar): " + (secondAttempt ? "OK" : "FAIL"));
		logout();

		// 4. Préstamo sin login
		System.out.println("\n--- Caso 4: Préstamo sin autenticación ---");
		BorrowBook borrow4 = new BorrowBook();
		borrow4.setArgs0("3333333332");
		boolean borrowed4 = stub.borrowBook(borrow4).get_return().getResponse();
		System.out.println("Préstamo sin login: " + (borrowed4 ? "OK" : "FAIL"));

		// 5. ISSN nulo o vacío
		System.out.println("\n--- Caso 5: ISSN nulo o vacío ---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");

		BorrowBook borrow5 = new BorrowBook();
		borrow5.setArgs0("");
		boolean borrowed5 = stub.borrowBook(borrow5).get_return().getResponse();
		System.out.println("Préstamo con ISSN vacío: " + (borrowed5 ? "OK" : "FAIL"));

		BorrowBook borrow6 = new BorrowBook();
		borrow6.setArgs0(null);
		boolean borrowed6 = stub.borrowBook(borrow6).get_return().getResponse();
		System.out.println("Préstamo con ISSN nulo: " + (borrowed6 ? "OK" : "FAIL"));
		logout();
	}

	private static void testReturnBook() throws RemoteException {
		System.out.println("\n--- testReturnBook ---");

		// 1. Devolución correcta
		System.out.println("--- Caso 1: Devolución correcta ---");
		loginAsAdmin();
		System.out.println("- Añadiendo un nuevo libro para prestar y devolver -");
		Book book = new Book();
		book.setName("LibroDevolucion1");
		book.setISSN("4444444444");
		book.setAuthors(new String[] { "AutorDevolucion" });
		AddBook addBook = new AddBook();
		addBook.setArgs0(book);
		stub.addBook(addBook);
		logout();

		// Usuario toma el libro
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		BorrowBook borrow = new BorrowBook();
		borrow.setArgs0("4444444444");
		stub.borrowBook(borrow);
		// Usuario devuelve el libro
		ReturnBook returnBook = new ReturnBook();
		returnBook.setArgs0("4444444444");
		boolean returned = stub.returnBook(returnBook).get_return().getResponse();
		System.out.println("Devolución realizada: " + (returned ? "OK" : "FAIL"));
		logout();

		// 2. Devolver libro no prestado
		System.out.println("\n--- Caso 2: Devolver libro no prestado ---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		ReturnBook returnBook2 = new ReturnBook();
		returnBook2.setArgs0("4444444444"); // Ya devuelto
		boolean returned2 = stub.returnBook(returnBook2).get_return().getResponse();
		System.out.println("Devolución libro no prestado: " + (returned2 ? "OK" : "FAIL"));
		logout();

		// 3. Devolver libro inexistente
		System.out.println("\n--- Caso 3: Devolver libro inexistente ---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");
		ReturnBook returnBook3 = new ReturnBook();
		returnBook3.setArgs0("9999999999"); // ISSN inexistente
		boolean returned3 = stub.returnBook(returnBook3).get_return().getResponse();
		System.out.println("Devolución libro inexistente: " + (returned3 ? "OK" : "FAIL"));
		logout();

		// 4. Devolver libro sin login
		System.out.println("\n--- Caso 4: Devolver sin login ---");
		ReturnBook returnBook4 = new ReturnBook();
		returnBook4.setArgs0("4444444444");
		boolean returned4 = stub.returnBook(returnBook4).get_return().getResponse();
		System.out.println("Devolución sin login: " + (returned4 ? "OK" : "FAIL"));

		// 5. Devolver con ISSN nulo o vacío
		System.out.println("\n--- Caso 5: ISSN nulo o vacío ---");
		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");

		ReturnBook returnBook5 = new ReturnBook();
		returnBook5.setArgs0("");
		boolean returned5 = stub.returnBook(returnBook5).get_return().getResponse();
		System.out.println("Devolución con ISSN vacío: " + (returned5 ? "OK" : "FAIL"));

		ReturnBook returnBook6 = new ReturnBook();
		returnBook6.setArgs0(null);
		boolean returned6 = stub.returnBook(returnBook6).get_return().getResponse();
		System.out.println("Devolución con ISSN nulo: " + (returned6 ? "OK" : "FAIL"));
		logout();
	}

	private static void testListBorrowedBooks() throws RemoteException {
		System.out.println("\n--- testListBorrowedBooks ---");

		loginAsUser("changePasswordTest", "changePasswordTestNewPassword");

		ListBorrowedBooks list = new ListBorrowedBooks();
		ListBorrowedBooksResponse response = stub.listBorrowedBooks(list);
		String[] libros = response.get_return().getBookNames();

		System.out.println("Libros prestados por el usuario:");
		if (libros != null && libros.length > 0) {
			for (String libro : libros) {
				System.out.println("- " + libro);
			}
		} else {
			System.out.println("Ningún libro prestado actualmente.");
		}

		logout();
	}

}