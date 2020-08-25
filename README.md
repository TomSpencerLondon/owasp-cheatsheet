# owasp-cheatsheet

## 1. SQL Injection
### Sanitise your input with prepared statements
### Bad code:

The following (Java) example is UNSAFE, and would allow an attacker to inject code into the query that would be executed by the database. The unvalidated "customerName" parameter that is simply appended to the query allows an attacker to inject any SQL code they want. Unfortunately, this method for accessing databases is all too common.

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = "
             + request.getParameter("customerName");
try {
    Statement statement = connection.createStatement( ... );
    ResultSet results = statement.executeQuery( query );
}
...
```

### Safe Java Prepared Statement Example:

The following code example uses a `PreparedStatement`, Java's implementation of a parameterized query, to execute the same database query.

```java
// This should REALLY be validated too
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```

**Safe C\# .NET Prepared Statement Example**:

With .NET, it's even more straightforward. The creation and execution of the query doesn't change. All you have to do is simply pass the parameters to the query using the `Parameters.Add()` call as shown here.

```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
try {
  OleDbCommand command = new OleDbCommand(query, connection);
  command.Parameters.Add(new OleDbParameter("customerName", CustomerName Name.Text));
  OleDbDataReader reader = command.ExecuteReader();
  // …
} catch (OleDbException se) {
  // error handling
}
```

## 2. Broken Authentication
### Have a strong password policy
### Bad:
Lacking validation that would enforce a strong password policy when the user creates their password.

### Good:
Notice how we're creating the new constraint violation here and disabling the default one as well – in case the password is not valid.
```java
public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {
 
    @Override
    public void initialize(ValidPassword arg0) {
    }
 
    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        PasswordValidator validator = new PasswordValidator(Arrays.asList(
           new LengthRule(8, 30), 
           new UppercaseCharacterRule(1), 
           new DigitCharacterRule(1), 
           new SpecialCharacterRule(1), 
           new NumericalSequenceRule(3,false), 
           new AlphabeticalSequenceRule(3,false), 
           new QwertySequenceRule(3,false),
           new WhitespaceRule()));
 
        RuleResult result = validator.validate(new PasswordData(password));
        if (result.isValid()) {
            return true;
        }
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(
          Joiner.on(",").join(validator.getMessages(result)))
          .addConstraintViolation();
        return false;
    }
}
```

## 3. Sensitive Data Exposure

### Make sure data in transit is protected

### Bad:
Plain HTTP connection without TLS

### Good:
Now that we are done with the certificate generation, let us add the following information in the Spring boot application.properties to enable TLS:
```java
server.ssl.key-store=classpath:medium.jks
server.ssl.key-store-type=pkcs12
server.ssl.key-store-password=password
server.ssl.key-password=password
server.ssl.key-alias=medium
server.port=8443
```

### Data at rest is protected

### Bad:
Usage of out of date or custom made encryption algorithms

### Good:
Use widely used strong encryption algorithms like Spring Security Crypto Module:

```java
StandardPasswordEncoder encoder = new StandardPasswordEncoder("secret");
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```

## 4. XML External Entities (XXE)

### Bad:
```java
File xmlFile = new File(“c://input.xml”);
DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
Document doc = dBuilder.parse(xmlFile);
```

### Good:
The insertion of the secret.txt file could allow the attacker to embed malicious code within the XML parser code. In order to protect against this form of attack we should add the following to our Java code:
```java
	DocumentBuilderFactor dbFactory = DocumentBuilderFactory.newInstance();
	dbFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

## 5. Broken Access Control

### Display exploitable account identifiers in the URL

### Bad:
The following URL allows the attacker to modify the URL in the browser to query any account they want:
	http://mybank.com/app/accountInfo?acct=#456

This is an example of bad code that would use this information to perform and unauthorized action that is not owned by the user submitting the form:
```java
stmt.setString(1, request.getParameter(“#123”);
ResultSet results = stmt.executeQuery();
```

### Good:
If a caller is not authorized to see the contents of a resource it should be as if the resource does not exist. In Java this is relatively easy to implement with @Preauthorize:

```java
@PreAuthorize(“hasAuthority(‘Admin’)”)
@RequestMapping(“/restricted”)
@ResponseBody
public String restricted() {
  return “restricted”;
}
```

### 6. Security Misconfiguration
