import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class JobPortal {

    static final int PORT = Integer.parseInt(
        System.getenv().getOrDefault("PORT", "8081"));

    static final Path DIR = Paths.get("unemployGen-data");
    static final Path USERS = DIR.resolve("users.txt");
    static final Path JOBS = DIR.resolve("jobs.txt");
    static final Path APPS = DIR.resolve("applications.txt");
    static final Path UPLOADS = DIR.resolve("uploads");

    static final Map<String,String> SESSIONS = new ConcurrentHashMap<>();
    static final SecureRandom RANDOM = new SecureRandom();

    public static void main(String[] args) throws Exception {

        Files.createDirectories(DIR);
        Files.createDirectories(UPLOADS);

        String adminEmail = System.getenv("ADMIN_EMAIL");
        String adminPass = System.getenv("ADMIN_PASSWORD");

        if (adminEmail != null && adminPass != null
            && !adminEmail.isBlank()
            && adminPass.length() >= 12) {

            adminEmail = adminEmail.trim().toLowerCase();

            if (find(USERS, adminEmail) == null) {
                String salt = newSalt();
                add(USERS, adminEmail, "admin", "Portal Administrator", "", salt, passwordHash(adminPass, salt), "");
                System.out.println("Admin account created.");
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        server.createContext("/", JobPortal::route);
        server.setExecutor(Executors.newFixedThreadPool(10));
        server.start();

        System.out.println("=========================================");
        System.out.println("    UnEmPloyGen ONLINE (Branded Edition)");
        System.out.println("=========================================");
        System.out.println("Open: http://localhost:" + PORT);
    }

    static void route(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            boolean post = ex.getRequestMethod().equals("POST");

            if (!post && !ex.getRequestMethod().equals("GET")) {
                send(ex, 405, page("Error", "<h2>Method not allowed</h2>"));
                return;
            }

            Map<String,String> p = params(ex);
            String user = currentUser(ex);

            if (path.startsWith("/uploads/")) {
                serveFile(ex, path.substring(9));
                return;
            }

            switch (path) {
                case "/": home(ex, p, user); break;
                case "/register": register(ex, p, post); break;
                case "/login": login(ex, p, post); break;
                case "/logout": logout(ex); break;
                case "/profile": profile(ex, p, post, user); break;
                case "/resume-builder": resumeBuilder(ex, user); break;
                case "/post": postJob(ex, p, post, user); break;
                case "/import-job": importJob(ex, p, post, user); break;
                case "/edit": editJob(ex, p, post, user); break;
                case "/delete": deleteJob(ex, p, post, user); break;
                case "/apply": apply(ex, p, post, user); break;
                case "/dashboard": dashboard(ex, user); break;
                case "/status": changeStatus(ex, p, post, user); break;
                case "/admin": admin(ex, user); break;
                case "/admin-action": adminAction(ex, p, post, user); break;
                default:
                    send(ex, 404, page("Not found", "<h2>Page not found</h2><a href='/'>Home</a>"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            if (!ex.getResponseHeaders().containsKey("Location")) {
                try {
                    send(ex, 500, page("Error", "<h2>Something went wrong.</h2>"));
                } catch (Exception ignored) {}
            }
        }
    }

    // ================= AUTHENTICATION & SESSIONS =================

    static String currentUser(HttpExchange ex) {
        String cookie = ex.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) return "";
        for (String part : cookie.split(";")) {
            String[] a = part.trim().split("=", 2);
            if (a.length == 2 && a[0].equals("UGSESSION")) {
                return SESSIONS.getOrDefault(a[1], "");
            }
        }
        return "";
    }

    static String role(String email) throws Exception {
        String[] u = find(USERS, email);
        return u == null || u.length < 7 ? "" : u[1];
    }

    static String name(String email) throws Exception {
        String[] u = find(USERS, email);
        return u == null || u.length < 7 ? "" : u[2];
    }

    static boolean isAdmin(String email) throws Exception {
        return role(email).equals("admin");
    }

    static boolean allowed(String email, String wanted) throws Exception {
        return !email.isEmpty() && role(email).equals(wanted);
    }

    static String newSalt() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    static String passwordHash(String password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            Base64.getDecoder().decode(salt),
            120000,
            256
        );
        try {
            byte[] hash = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } finally {
            spec.clearPassword();
        }
    }

    // ================= REGISTER & LOGIN =================

    static void register(HttpExchange ex, Map<String,String> p, boolean post) throws Exception {
        String msg = "";
        if (post) {
            String n = g(p,"name");
            String email = g(p,"email").toLowerCase();
            String phone = g(p,"phone");
            String pass = g(p,"password");
            String r = g(p,"role");

            if (n.isEmpty() || email.isEmpty() || phone.isEmpty()) {
                msg = "Please complete all required fields.";
            } else if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
                msg = "Enter a valid email address.";
            } else if (pass.length() < 8) {
                msg = "Password must contain at least 8 characters.";
            } else if (!r.equals("seeker") && !r.equals("employer")) {
                msg = "Invalid account type.";
            } else if (find(USERS,email) != null) {
                msg = "This email is already registered.";
            }

            if (msg.isEmpty()) {
                String salt = newSalt();
                add(USERS, email, r, n, phone, salt, passwordHash(pass,salt), "");
                redirect(ex, "/login");
                return;
            }
        }

        String html = error(msg) +
            "<h2>Create your account</h2>" +
            "<p class=muted>Join <span class=brand-accent>UnEmPloyGen</span> today.</p>" +
            "<form method=post>" +
            field("name","Full name",p,true) +
            field("email","Email address",p,true) +
            field("phone","Phone number",p,true) +
            "<label>Account type<select name=role>" +
            "<option value=seeker>Job Seeker</option>" +
            "<option value=employer>Employer</option>" +
            "</select></label>" +
            "<label>Password<input type=password name=password minlength=8 required></label>" +
            "<button>Create Account</button></form>";

        send(ex, 200, page("Register", html));
    }

    static void login(HttpExchange ex, Map<String,String> p, boolean post) throws Exception {
        String msg = "";
        if (post) {
            String email = g(p,"email").toLowerCase();
            String pass = g(p,"password");
            String[] u = find(USERS, email);

            if (u != null && u.length >= 7) {
                String hash = passwordHash(pass, u[4]);
                if (MessageDigest.isEqual(hash.getBytes(StandardCharsets.UTF_8), u[5].getBytes(StandardCharsets.UTF_8))) {
                    String token = UUID.randomUUID().toString();
                    SESSIONS.put(token, email);
                    ex.getResponseHeaders().add("Set-Cookie", "UGSESSION=" + token + "; Path=/; HttpOnly; SameSite=Lax");
                    redirect(ex, "/dashboard");
                    return;
                }
            }
            msg = "Incorrect email or password.";
        }

        String html = error(msg) +
            "<h2>Welcome back</h2>" +
            "<p class=muted>Log into <span class=brand-accent>UnEmPloyGen</span></p>" +
            "<form method=post>" +
            field("email","Email address",p,true) +
            "<label>Password<input type=password name=password required></label>" +
            "<button>Login</button></form>" +
            "<p>New here? <a href='/register'>Create account</a></p>";

        send(ex, 200, page("Login", html));
    }

    static void logout(HttpExchange ex) throws IOException {
        String cookie = ex.getRequestHeaders().getFirst("Cookie");
        if (cookie != null) {
            for (String part : cookie.split(";")) {
                String[] a = part.trim().split("=", 2);
                if (a.length == 2 && a[0].equals("UGSESSION")) {
                    SESSIONS.remove(a[1]);
                }
            }
        }
        ex.getResponseHeaders().add("Set-Cookie", "UGSESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        redirect(ex, "/");
    }

    // ================= PROFILE & RESUME MANAGEMENT =================

    static void profile(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (user.isEmpty()) {
            redirect(ex, "/login");
            return;
        }

        String msg = "";
        String[] u = find(USERS, user);
        if (u == null) {
            redirect(ex, "/login");
            return;
        }

        if (post) {
            String n = g(p, "name");
            String phone = g(p, "phone");
            
            if (n.isEmpty() || phone.isEmpty()) {
                msg = "Name and phone number cannot be empty.";
            } else {
                u[2] = n;
                u[3] = phone;
                replace(USERS, user, u);
                msg = "Profile updated successfully!";
            }
        }

        Map<String,String> v = new HashMap<>();
        v.put("name", u[2]);
        v.put("phone", u[3]);

        StringBuilder sb = new StringBuilder();
        sb.append(error(msg));
        sb.append("<h2>Manage Profile & Resume</h2>");
        sb.append("<form method=post>");
        sb.append(field("name", "Full Name", v, true));
        sb.append(field("phone", "Phone Number", v, true));
        sb.append("<button>Save Profile</button>");
        sb.append("</form>");

        sb.append("<hr style='border-color:#294464; margin:25px 0'>");
        sb.append("<h3>Resume Management</h3>");
        
        Path resumePath = UPLOADS.resolve("resume_" + user.hashCode() + ".pdf");
        if (Files.exists(resumePath)) {
            sb.append("<p>Current Resume: <a href='/uploads/resume_").append(user.hashCode()).append(".pdf' target=_blank>Download / View Resume</a></p>");
        } else {
            sb.append("<p class=muted>No resume uploaded yet.</p>");
        }

        sb.append("<p><a class=btn href='/resume-builder'>Generate Professional Resume (PDF Builder)</a></p>");

        send(ex, 200, page("Profile", sb.toString()));
    }

    // ================= PDF RESUME BUILDER =================

    static void resumeBuilder(HttpExchange ex, String user) throws Exception {
        if (!allowed(user, "seeker")) {
            redirect(ex, "/login");
            return;
        }

        String[] u = find(USERS, user);
        String name = u != null ? u[2] : "Job Seeker";
        String email = user;
        String phone = u != null ? u[3] : "";

        String html = "<div id='resume-doc' style='background:white; color:black; padding:30px; border-radius:8px;'>" +
            "<h1>" + esc(name) + "</h1>" +
            "<p>Email: " + esc(email) + " | Phone: " + esc(phone) + "</p>" +
            "<hr>" +
            "<h3>Professional Summary</h3>" +
            "<p>Motivated professional seeking new career opportunities in a dynamic environment.</p>" +
            "<h3>Experience</h3>" +
            "<p><b>Software Developer / Specialist</b> - Company Name (2024 - Present)</p>" +
            "<ul><li>Built robust software solutions and automated workflows.</li></ul>" +
            "<h3>Education</h3>" +
            "<p><b>Bachelor's Degree</b> - University Name</p>" +
            "</div>" +
            "<br><button onclick='window.print()' class=btn>Download / Print as PDF</button> " +
            "<a href='/profile' class=btn style='background:#36516e'>Back to Profile</a>" +
            "<style>@media print { body { background: white; } header, footer, button, a { display: none !important; } }</style>";

        send(ex, 200, page("Resume Builder", html));
    }

    static void serveFile(HttpExchange ex, String filename) throws IOException {
        filename = Paths.get(filename).getFileName().toString();
        Path filePath = UPLOADS.resolve(filename);

        if (!Files.exists(filePath)) {
            send(ex, 404, page("Not Found", "<h2>File not found</h2>"));
            return;
        }

        byte[] bytes = Files.readAllBytes(filePath);
        ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ================= HOME / JOB SEARCH =================

    static void home(HttpExchange ex, Map<String,String> p, String user) throws Exception {
        String q = g(p,"q").toLowerCase();
        List<String[]> jobs = rows(JOBS);
        Collections.reverse(jobs);

        StringBuilder sb = new StringBuilder();

        sb.append("<div class='hero-banner'>");
        sb.append("<h1>Find your next opportunity on <span class='brand-highlight'>UnEmPloyGen</span></h1>");
        sb.append("<p class='hero-sub'>The next-generation career portal linking top talent with leading employers.</p>");
        sb.append("</div>");

        sb.append("<form method=get style='margin-top:20px'>");
        sb.append("<input name=q placeholder='Search job title, company, or city...' value='");
        sb.append(esc(g(p,"q"))).append("'>");
        sb.append("<button>Search Jobs</button></form>");

        int count = 0;
        for (String[] j : jobs) {
            if (j.length < 8 || !j[6].equals("active")) continue;
            String all = (j[2] + " " + j[3] + " " + j[4]).toLowerCase();
            if (!all.contains(q)) continue;
            count++;

            String externalUrl = j.length >= 9 ? j[8] : "";

            sb.append("<div class=card>");
            sb.append("<h3>").append(esc(j[2])).append("</h3>");
            sb.append("<b>").append(esc(j[3])).append("</b>");
            sb.append("<p class=muted>").append(esc(j[4])).append("</p>");
            sb.append("<p>").append(esc(j[5])).append("</p>");

            if (!externalUrl.isEmpty()) {
                sb.append("<a class=btn target=_blank href='").append(esc(externalUrl)).append("'>Apply on External Site &#8599;</a>");
            } else if (user.isEmpty() || !role(user).equals("seeker")) {
                sb.append("<a class=btn href='/login'>Login to Apply</a>");
            } else {
                sb.append("<a class=btn href='/apply?id=").append(esc(j[0])).append("'>Apply Now</a>");
            }
            sb.append("</div>");
        }

        if (count == 0) {
            sb.append("<p class=muted style='margin-top:20px;'>No active job listings match your search.</p>");
        }

        send(ex, 200, page("Find Jobs", sb.toString()));
    }

    // ================= POST & IMPORT JOBS =================

    static void postJob(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!allowed(user, "employer") && !isAdmin(user)) {
            redirect(ex, "/login");
            return;
        }

        String msg = "";
        if (post) {
            if (g(p,"title").isEmpty() || g(p,"company").isEmpty()) {
                msg = "Job title and company are required.";
            }

            String externalUrl = g(p,"external_url");
            if (!externalUrl.isEmpty() && (!externalUrl.startsWith("http://") && !externalUrl.startsWith("https://"))) {
                msg = "External link must start with http:// or https://";
            }

            if (msg.isEmpty()) {
                add(JOBS,
                    UUID.randomUUID().toString(),
                    user,
                    g(p,"title"),
                    g(p,"company"),
                    g(p,"location"),
                    g(p,"description"),
                    "active",
                    java.time.LocalDate.now().toString(),
                    externalUrl
                );
                redirect(ex, "/dashboard");
                return;
            }
        }

        String html = error(msg) +
            "<h2>Publish a job on <span class=brand-accent>UnEmPloyGen</span></h2>" +
            "<p class=muted>Post an internal opening or attach an external link.</p>" +
            "<form method=post>" +
            field("title","Job title",p,true) +
            field("company","Company",p,true) +
            field("location","City / Remote",p,false) +
            field("external_url","External Link (Optional)",p,false) +
            area("description","Job description",p) +
            "<button>Publish Job</button></form>";

        send(ex, 200, page("Post Job", html));
    }

    static void importJob(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!allowed(user, "employer") && !isAdmin(user)) {
            redirect(ex, "/login");
            return;
        }

        String msg = "";
        if (post) {
            String title = g(p, "title");
            String company = g(p, "company");
            String extUrl = g(p, "external_url");

            if (title.isEmpty() || company.isEmpty() || extUrl.isEmpty()) {
                msg = "Title, Company, and External Job URL are all required.";
            } else if (!extUrl.startsWith("http://") && !extUrl.startsWith("https://")) {
                msg = "Please provide a valid web URL starting with http:// or https://";
            }

            if (msg.isEmpty()) {
                add(JOBS,
                    UUID.randomUUID().toString(),
                    user,
                    title,
                    company,
                    g(p, "location").isEmpty() ? "Remote / External" : g(p, "location"),
                    g(p, "description").isEmpty() ? "Imported external listing. Click below to view full details and apply on the source website." : g(p, "description"),
                    "active",
                    java.time.LocalDate.now().toString(),
                    extUrl
                );
                redirect(ex, "/dashboard");
                return;
            }
        }

        String html = error(msg) +
            "<h2>Import External Job to <span class=brand-accent>UnEmPloyGen</span></h2>" +
            "<p class=muted>Bring in listings from external company sites or career portals.</p>" +
            "<form method=post>" +
            field("title", "Job Title", p, true) +
            field("company", "Company Name", p, true) +
            field("location", "Location", p, false) +
            field("external_url", "External Job URL", p, true) +
            area("description", "Brief Summary", p) +
            "<button style='background:#10a37f'>Import Job Listing</button>" +
            "</form>";

        send(ex, 200, page("Import Job", html));
    }

    static void editJob(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        String[] j = find(JOBS, g(p,"id"));
        if (j == null || j.length < 8 || (!j[1].equals(user) && !isAdmin(user))) {
            send(ex, 403, page("Access denied", "<h2>Not allowed</h2>"));
            return;
        }

        if (post) {
            if (g(p,"title").isEmpty() || g(p,"company").isEmpty()) {
                send(ex, 400, page("Error", "<h2>Title and company are required.</h2>"));
                return;
            }

            String externalUrl = g(p,"external_url");
            String[] updated = {
                j[0],
                j[1],
                g(p,"title"),
                g(p,"company"),
                g(p,"location"),
                g(p,"description"),
                j[6],
                j[7],
                externalUrl
            };

            replace(JOBS, j[0], updated);
            redirect(ex, "/dashboard");
            return;
        }

        Map<String,String> v = new HashMap<>();
        v.put("title", j[2]);
        v.put("company", j[3]);
        v.put("location", j[4]);
        v.put("description", j[5]);
        v.put("external_url", j.length >= 9 ? j[8] : "");

        String html = "<h2>Edit job</h2><form method=post>" +
            field("title","Job title",v,true) +
            field("company","Company",v,true) +
            field("location","City",v,false) +
            field("external_url","External Link",v,false) +
            area("description","Description",v) +
            "<button>Save Changes</button></form>";

        send(ex, 200, page("Edit Job", html));
    }

    static void deleteJob(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!post) {
            send(ex, 405, page("Error", "<h2>Use the delete form.</h2>"));
            return;
        }
        String[] j = find(JOBS, g(p,"id"));
        if (j != null && j.length >= 8 && (j[1].equals(user) || isAdmin(user))) {
            remove(JOBS, j[0]);
        }
        redirect(ex, "/dashboard");
    }

    // ================= APPLY & DASHBOARD =================

    static void apply(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!allowed(user, "seeker")) {
            redirect(ex, "/login");
            return;
        }

        String[] j = find(JOBS, g(p,"id"));
        if (j == null || j.length < 8 || !j[6].equals("active")) {
            send(ex, 404, page("Unavailable", "<h2>This job is unavailable.</h2>"));
            return;
        }

        if (j.length >= 9 && !j[8].isEmpty()) {
            redirect(ex, j[8]);
            return;
        }

        String msg = "";
        if (post) {
            if (g(p,"message").isEmpty()) {
                msg = "Please write a short message.";
            }
            for (String[] a : rows(APPS)) {
                if (a.length >= 6 && a[1].equals(j[0]) && a[2].equals(user)) {
                    msg = "You have already applied for this job.";
                    break;
                }
            }

            if (msg.isEmpty()) {
                add(APPS,
                    UUID.randomUUID().toString(),
                    j[0],
                    user,
                    g(p,"message"),
                    "Pending",
                    java.time.LocalDate.now().toString()
                );
                redirect(ex, "/dashboard");
                return;
            }
        }

        String html = error(msg) +
            "<h2>Apply for " + esc(j[2]) + "</h2>" +
            "<p>" + esc(j[3]) + "</p>" +
            "<form method=post>" +
            area("message","Message to employer",p) +
            "<button>Submit Application</button></form>";

        send(ex, 200, page("Apply", html));
    }

    static void dashboard(HttpExchange ex, String user) throws Exception {
        if (user.isEmpty()) {
            redirect(ex, "/login");
            return;
        }

        String r = role(user);
        StringBuilder sb = new StringBuilder();
        sb.append("<h2>Hello, ").append(esc(name(user))).append("</h2>");

        if (r.equals("employer")) {
            sb.append("<h3>Employer Listings</h3>");
            sb.append("<p><a class=btn href='/post'>Post New Job</a> &nbsp; <a class=btn style='background:#10a37f' href='/import-job'>Import External Link</a></p>");

            for (String[] j : rows(JOBS)) {
                if (j.length < 8 || !j[1].equals(user)) continue;
                sb.append("<div class=card>");
                sb.append("<h3>").append(esc(j[2])).append("</h3>");
                sb.append("<p>").append(esc(j[3])).append("</p>");
                sb.append("<p>Status: ").append(esc(j[6])).append("</p>");
                if (j.length >= 9 && !j[8].isEmpty()) {
                    sb.append("<p class=muted>External Link: <a href='").append(esc(j[8])).append("' target=_blank>").append(esc(j[8])).append("</a></p>");
                }
                sb.append("<a href='/edit?id=").append(esc(j[0])).append("'>Edit</a> | ");

                sb.append("<form method=post action='/delete' style='display:inline'>");
                sb.append("<input type=hidden name=id value='").append(esc(j[0])).append("'>");
                sb.append("<button style='background:#632c3b; padding:6px 12px'>Delete</button></form>");
                sb.append("</div>");

                if (j.length < 9 || j[8].isEmpty()) {
                    sb.append("<h4>Applicants</h4>");
                    for (String[] a : rows(APPS)) {
                        if (a.length < 6 || !a[1].equals(j[0])) continue;
                        sb.append("<div class=card>");
                        sb.append("<b>Applicant: ").append(esc(name(a[2]))).append("</b>");
                        sb.append("<p>Message: ").append(esc(a[3])).append("</p>");
                        sb.append("<p>Status: ").append(esc(a[4])).append("</p>");
                        sb.append("<p><a href='/uploads/resume_").append(a[2].hashCode()).append(".pdf' target=_blank>Download Seeker Resume</a></p>");

                        sb.append("<form method=post action='/status'>");
                        sb.append("<input type=hidden name=id value='").append(esc(a[0])).append("'>");
                        sb.append("<select name=status>");
                        sb.append("<option>Pending</option><option>Shortlisted</option><option>Rejected</option><option>Selected</option>");
                        sb.append("</select><button>Update Status</button></form>");
                        sb.append("</div>");
                    }
                }
            }
        } else if (r.equals("seeker")) {
            sb.append("<p><a class=btn href='/profile'>Edit Profile & Manage Resume</a></p>");
            sb.append("<h3>My Applications</h3>");

            for (String[] a : rows(APPS)) {
                if (a.length < 6 || !a[2].equals(user)) continue;
                String[] j = find(JOBS, a[1]);
                sb.append("<div class=card>");
                sb.append("<b>").append(j == null ? "Job" : esc(j[2])).append("</b>");
                sb.append("<p>Status: ").append(esc(a[4])).append("</p>");
                sb.append("<p>Applied: ").append(esc(a[5])).append("</p>");
                sb.append("</div>");
            }
        } else if (r.equals("admin")) {
            sb.append("<a class=btn href='/admin'>Open Admin Dashboard</a>");
        }

        send(ex, 200, page("Dashboard", sb.toString()));
    }

    static void changeStatus(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!post) {
            send(ex, 405, page("Error","<h2>POST required</h2>"));
            return;
        }
        String[] a = find(APPS, g(p,"id"));
        if (!allowed(user, "employer") || a == null || a.length < 6) {
            send(ex, 403, page("Access denied","<h2>Not allowed</h2>"));
            return;
        }
        String[] j = find(JOBS, a[1]);
        if (j == null || !j[1].equals(user)) {
            send(ex, 403, page("Access denied","<h2>Not allowed</h2>"));
            return;
        }
        String s = g(p,"status");
        if (Arrays.asList("Pending","Shortlisted","Rejected","Selected").contains(s)) {
            a[4] = s;
            replace(APPS, a[0], a);
        }
        redirect(ex, "/dashboard");
    }

    // ================= ADMIN CONTROLS =================

    static void admin(HttpExchange ex, String user) throws Exception {
        if (!isAdmin(user)) {
            send(ex, 403, page("Access denied", "<h2>Administrator access required</h2>"));
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<h2>Administrator Dashboard</h2>");
        sb.append("<p><a class=btn href='/import-job'>Import External Job</a></p>");

        sb.append("<div class=card><h3>Users (").append(rows(USERS).size()).append(")</h3>");
        for (String[] u : rows(USERS)) {
            if (u.length < 7) continue;
            sb.append("<p><b>").append(esc(u[2])).append("</b> | ").append(esc(u[1])).append(" | ").append(esc(u[0]));
            sb.append(" <form method=post action='/admin-action' style='display:inline'><input type=hidden name=action value='delete_user'><input type=hidden name=target value='").append(esc(u[0])).append("'><button style='background:#632c3b; padding:4px 8px; font-size:12px;'>Delete User</button></form></p>");
        }
        sb.append("</div>");

        sb.append("<div class=card><h3>Jobs (").append(rows(JOBS).size()).append(")</h3>");
        for (String[] j : rows(JOBS)) {
            if (j.length < 8) continue;
            sb.append("<p><b>").append(esc(j[2])).append("</b> - ").append(esc(j[3])).append(" | Status: ").append(esc(j[6]));
            if (j.length >= 9 && !j[8].isEmpty()) {
                sb.append(" <b>[External Link]</b>");
            }
            sb.append(" <form method=post action='/admin-action' style='display:inline'><input type=hidden name=action value='delete_job'><input type=hidden name=target value='").append(esc(j[0])).append("'><button style='background:#632c3b; padding:4px 8px; font-size:12px;'>Remove Job</button></form></p>");
        }
        sb.append("</div>");

        send(ex, 200, page("Admin Dashboard", sb.toString()));
    }

    static void adminAction(HttpExchange ex, Map<String,String> p, boolean post, String user) throws Exception {
        if (!isAdmin(user) || !post) {
            send(ex, 403, page("Access denied", "<h2>Not allowed</h2>"));
            return;
        }
        String action = g(p, "action");
        String target = g(p, "target");

        if (action.equals("delete_user") && !target.equals(user)) {
            remove(USERS, target);
        } else if (action.equals("delete_job")) {
            remove(JOBS, target);
        }
        redirect(ex, "/admin");
    }

    // ================= STORAGE HELPERS =================

    static synchronized List<String[]> rows(Path f) throws IOException {
        List<String[]> out = new ArrayList<>();
        if (!Files.exists(f)) return out;
        for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
            if (!line.isBlank()) {
                out.add(line.split("\t", -1));
            }
        }
        return out;
    }

    static String[] find(Path f, String id) throws IOException {
        for (String[] r : rows(f)) {
            if (r.length > 0 && r[0].equals(id)) {
                return r;
            }
        }
        return null;
    }

    static synchronized void add(Path f, String... values) throws IOException {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) s.append('\t');
            s.append(clean(values[i]));
        }
        s.append('\n');
        Files.writeString(f, s.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    static synchronized void replace(Path f, String id, String[] values) throws IOException {
        List<String[]> all = rows(f);
        List<String> out = new ArrayList<>();
        for (String[] r : all) {
            if (r[0].equals(id)) r = values;
            out.add(String.join("\t", r));
        }
        Files.write(f, out, StandardCharsets.UTF_8);
    }

    static synchronized void remove(Path f, String id) throws IOException {
        List<String[]> all = rows(f);
        List<String> out = new ArrayList<>();
        for (String[] r : all) {
            if (!r[0].equals(id)) {
                out.add(String.join("\t", r));
            }
        }
        Files.write(f, out, StandardCharsets.UTF_8);
    }

    static String clean(String s) {
        return s == null ? "" : s.replaceAll("[\\t\\r\\n]+", " ");
    }

    static String g(Map<String,String> p, String k) {
        return p.getOrDefault(k, "").trim();
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    static String field(String n, String label, Map<String,String> p, boolean required) {
        return "<label>" + esc(label) +
            "<input name='" + n + "' value='" + esc(g(p, n)) + "'" +
            (required ? " required" : "") + "></label>";
    }

    static String area(String n, String label, Map<String,String> p) {
        return "<label>" + esc(label) +
            "<textarea name='" + n + "' rows=5>" +
            esc(g(p, n)) + "</textarea></label>";
    }

    static String error(String msg) {
        return msg.isEmpty() ? "" : "<div class=err>" + esc(msg) + "</div>";
    }

    // ================= PAGE DESIGN & BRANDING =================

    static String page(String title, String body) {
        return "<!DOCTYPE html><html lang='en'><head>" +
            "<meta charset='UTF-8'>" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>" + esc(title) + " | UnEmPloyGen</title>" +
            "<style>" +
            "*{box-sizing:border-box}" +
            "body{margin:0;background:#060d17;color:#eaf2ff;font-family:System-UI,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;line-height:1.6}" +

            "/* Header & Brand Styling */" +
            "header{background:#0b192e;padding:16px 20px;border-bottom:2px solid #1a385c;box-shadow:0 4px 20px rgba(0,0,0,0.4)}" +
            ".nav-container{max-width:900px;margin:auto;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}" +
            ".brand-logo{display:inline-flex;align-items:center;gap:10px;text-decoration:none}" +
            ".brand-badge{background:linear-gradient(135deg,#00f2fe,#4facfe);color:#060d17;font-weight:900;padding:5px 10px;border-radius:8px;font-size:15px;letter-spacing:0.5px}" +
            ".brand-title{font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.5px}" +
            ".brand-accent{color:#00f2fe;font-weight:bold}" +

            "nav{display:flex;gap:14px;flex-wrap:wrap}" +
            "nav a{color:#a5cbef;text-decoration:none;font-weight:600;font-size:15px;transition:color 0.2s}" +
            "nav a:hover{color:#00f2fe}" +

            "main{max-width:900px;margin:auto;padding:25px 20px}" +

            "/* Hero Banner */" +
            ".hero-banner{background:linear-gradient(180deg,#0f2744 0%,#081426 100%);border:1px solid #1e416a;padding:28px 22px;border-radius:16px;text-align:center;margin-bottom:20px}" +
            ".hero-banner h1{margin:0 0 10px;font-size:26px;color:#ffffff}" +
            ".brand-highlight{color:#00f2fe;background:linear-gradient(90deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:900}" +
            ".hero-sub{color:#9bb5d4;margin:0;font-size:15px}" +

            "h1,h2{color:#00f2fe;font-weight:700}" +
            ".card{background:#0d2038;padding:20px;border:1px solid #1c395e;border-radius:14px;margin:16px 0;box-shadow:0 4px 12px rgba(0,0,0,0.25)}" +
            ".muted{color:#8da5c4}" +

            "input,textarea,select{width:100%;padding:14px;margin:7px 0 16px;border-radius:10px;border:1px solid #234775;background:#071424;color:white;font-size:16px}" +
            "input:focus,textarea:focus,select:focus{outline:none;border-color:#00f2fe;box-shadow:0 0 8px rgba(0,242,254,0.3)}" +
            "label{display:block;margin-top:12px;font-weight:600;color:#c0d8f0}" +

            "button,.btn{display:inline-block;background:linear-gradient(135deg,#00c6ff,#0072ff);color:white;padding:12px 20px;border:0;border-radius:10px;text-decoration:none;font-weight:bold;cursor:pointer;min-height:48px;box-shadow:0 4px 14px rgba(0,114,255,0.4);transition:transform 0.1s}" +
            "button:active,.btn:active{transform:scale(0.98)}" +
            ".err{background:#5c1d29;color:#ffcdd2;padding:14px;border-radius:10px;border:1px solid #b71c1c}" +

            "a{color:#00f2fe}" +
            "footer{margin-top:50px;border-top:1px solid #1a385c;padding:20px 0;text-align:center}" +
            "</style></head><body>" +

            "<header><div class='nav-container'>" +
            "<a href='/' class='brand-logo'>" +
            "<span class='brand-badge'>uG</span>" +
            "<span class='brand-title'>UnEmPloy<span class='brand-accent'>Gen</span></span>" +
            "</a>" +
            "<nav>" +
            "<a href='/'>Find Jobs</a>" +
            "<a href='/register'>Register</a>" +
            "<a href='/login'>Login</a>" +
            "<a href='/dashboard'>Dashboard</a>" +
            "<a href='/logout'>Logout</a>" +
            "</nav>" +
            "</div></header>" +

            "<main>" + body +
            "<footer><p class=muted>&copy; 2026 <strong style='color:#eaf2ff'>UnEmPloyGen</strong> | Building Future Careers.</p></footer>" +
            "</main></body></html>";
    }

    static Map<String,String> params(HttpExchange ex) throws IOException {
        Map<String,String> m = new HashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q != null) parse(q, m);
        if (ex.getRequestMethod().equals("POST")) {
            parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8), m);
        }
        return m;
    }

    static void parse(String s, Map<String,String> m) {
        for (String part : s.split("&")) {
            if (part.isEmpty()) continue;
            String[] a = part.split("=", 2);
            try {
                String k = URLDecoder.decode(a[0], "UTF-8");
                String v = a.length > 1 ? URLDecoder.decode(a[1], "UTF-8") : "";
                m.put(k, v);
            } catch (Exception ignored) {}
        }
    }

    static void send(HttpExchange ex, int code, String html) throws IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.getResponseHeaders().set("X-Frame-Options", "DENY");
        ex.getResponseHeaders().set("Referrer-Policy", "strict-origin-when-cross-origin");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) {
            o.write(b);
        }
    }

    static void redirect(HttpExchange ex, String path) throws IOException {
        ex.getResponseHeaders().set("Location", path);
        ex.sendResponseHeaders(303, -1);
        ex.close();
    }
}
