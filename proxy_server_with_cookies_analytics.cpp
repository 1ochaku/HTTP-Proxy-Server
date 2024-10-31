#include <boost/asio.hpp>
#include <iostream>
#include <regex>
#include <unordered_map>
#include <string>
#include <iomanip> // For std::setw

using boost::asio::ip::tcp;

class ProxyServer
{
public:
    ProxyServer(boost::asio::io_context &io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        startAccept();
    }

    // Print analytics for all domains and the most frequently accessed domain
    // Print analytics for all domains and the most frequently accessed domain
    void addAccess(const std::string &domain)
    {
        domainAccessCount[domain]++;
        // Simulating cookie count for demo
        cookiePatterns[domain] = rand() % 10; // Random cookie count for demo
    }

    void printAnalytics()
    {
        // Debug output to check data
        std::cout << "Debug - Domain Access Count:\n";
        for (const auto &domainPair : domainAccessCount)
        {
            std::cout << "Domain: " << domainPair.first << ", Access Count: " << domainPair.second << "\n";
        }

        std::cout << "\nDebug - Cookie Patterns:\n";
        for (const auto &cookiePair : cookiePatterns)
        {
            std::cout << "Domain: " << cookiePair.first << ", Total Cookies: " << cookiePair.second << "\n";
        }

        // Display analytics for all domains
        std::cout << "\nDomain Access Frequency and Total Cookie Count:\n";
        for (const auto &domainPair : domainAccessCount)
        {
            const std::string &domain = domainPair.first;
            int accessCount = domainPair.second;
            int cookieCount = cookiePatterns[domain]; // Total cookies for this domain

            std::cout << "\nDomain: " << domain << "\n";
            std::cout << "  Access Count: " << accessCount << "\n";
            std::cout << "  Total Cookies: " << cookieCount << "\n";
        }

        // Display the most frequently accessed domain
        auto maxDomainIt = std::max_element(domainAccessCount.begin(), domainAccessCount.end(),
                                            [](const auto &a, const auto &b)
                                            { return a.second < b.second; });

        if (maxDomainIt != domainAccessCount.end())
        {
            const std::string &mostAccessedDomain = maxDomainIt->first;
            int maxAccessCount = maxDomainIt->second;
            int maxCookieCount = cookiePatterns[mostAccessedDomain]; // Total cookies for the most accessed domain

            std::cout << "\nMost accessed domain: " << mostAccessedDomain << " with " << maxAccessCount << " accesses\n";
            std::cout << "Total Cookies: " << maxCookieCount << "\n";
        }
    }

private:
    // Structure: clientCookies[clientId][domainName][cookieName] = cookieValue
    // clientId = IP address + Port
    std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, std::string>>> clientCookies;

    // Structure to track domain access frequency
    std::unordered_map<std::string, int> domainAccessCount;

    // Structure to track cookie patterns
    std::unordered_map<std::string, int> cookiePatterns;

    // Getting the unique identifier
    std::string getClientId(const boost::asio::ip::tcp::socket &socket)
    {
        auto remote_endpoint = socket.remote_endpoint();
        std::string clientIp = remote_endpoint.address().to_string();
        std::string fixedPort = "80";
        return clientIp + ":" + fixedPort;
    }

    // Listens to the incoming requests and make a socket for that
    void startAccept()
    {
        auto newSession = std::make_shared<tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*newSession, [this, newSession](boost::system::error_code ec)
                               {
            if (!ec)
            {
                handleRequest(newSession);
            }
            startAccept(); });
    }

    // For trimming the white spaces
    std::string trim(const std::string &str)
    {
        size_t start = str.find_first_not_of(" \t\r\n");
        size_t end = str.find_last_not_of(" \t\r\n");
        return (start == std::string::npos || end == std::string::npos) ? "" : str.substr(start, end - start + 1);
    }

    // For separating the port number and domain names and setting the path as well
    bool parseRequest(const std::string &requestLine, std::istream &headerStream, std::string &host, std::string &path, std::string &version, std::string &port)
    {
        std::string method;
        std::istringstream requestStream(requestLine);
        requestStream >> method >> path >> version;

        if (path.find("http://") == 0)
        {
            path = path.substr(7);
        }

        size_t pathStart = path.find('/');
        if (pathStart != std::string::npos)
        {
            path = path.substr(pathStart);
        }
        else
        {
            path = "/"; // Default path if none is specified
        }

        if (path.empty() || path[0] != '/')
        {
            path = "/" + path;
        }

        std::string headerLine;
        while (std::getline(headerStream, headerLine) && headerLine != "\r")
        {
            if (headerLine.find("Host: ") == 0)
            {
                std::string hostLine = headerLine.substr(6);
                size_t colonPos = hostLine.find(':');
                if (colonPos != std::string::npos)
                {
                    host = hostLine.substr(0, colonPos);
                    port = hostLine.substr(colonPos + 1);
                }
                else
                {
                    host = hostLine;
                }
            }
        }

        if (port.empty())
        {
            port = "80";
        }

        host = trim(host);
        port = trim(port);

        return !host.empty();
    }

    // Function to forward the request to the target server and handle the response
    void forwardRequest(std::shared_ptr<tcp::socket> clientSocket, const std::string &host, const std::string &path, const std::string &version, const std::string &port)
    {
        auto serverSocket = std::make_shared<tcp::socket>(clientSocket->get_executor());
        tcp::resolver resolver(clientSocket->get_executor());
        boost::system::error_code resolveError;
        auto endpoints = resolver.resolve(host, port, resolveError);

        if (resolveError)
        {
            std::cerr << "DNS resolution failed: " << resolveError.message() << std::endl;
            return;
        }

        std::cout << "DNS resolution successful. Connecting to the first endpoint..." << std::endl;

        boost::asio::async_connect(*serverSocket, endpoints, [this, clientSocket, serverSocket, path, version, host, port](boost::system::error_code ec, tcp::endpoint endpoint)
                                   {
            if (!ec) {
                std::cout << "Connected to server." << std::endl;

                std::string forwardRequest = "GET " + path + " " + version + "\r\n" +
                                             "Host: " + host + "\r\n";

                addCookiesToRequest(forwardRequest, getClientId(*clientSocket), host);

                forwardRequest += "Connection: close\r\n\r\n";

                // Track domain access frequency
                domainAccessCount[host]++;
                std::cout << "Domain Access frequency for " << host << ": " << domainAccessCount[host] << std::endl;

                boost::asio::async_write(*serverSocket, boost::asio::buffer(forwardRequest), [this, clientSocket, serverSocket, host](boost::system::error_code ec, std::size_t) {
                    if (!ec) {
                        std::cout << "Request forwarded to server." << std::endl;

                        auto responseBuffer = std::make_shared<boost::asio::streambuf>();
                        auto accumulatedResponse = std::make_shared<std::string>();

                        readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse, host);
                    } else {
                        std::cerr << "Error forwarding request to server: " << ec.message() << std::endl;
                    }
                });
            } else {
                std::cerr << "Error connecting to server: " << ec.message() << std::endl;
            } });
    }

    // Function to continuously read from the server and accumulate data
    void readServerResponse(std::shared_ptr<tcp::socket> clientSocket, std::shared_ptr<tcp::socket> serverSocket, std::shared_ptr<boost::asio::streambuf> responseBuffer, std::shared_ptr<std::string> accumulatedResponse, const std::string &domain)
    {
        boost::asio::async_read(*serverSocket, *responseBuffer, boost::asio::transfer_at_least(1),
                                [this, clientSocket, serverSocket, responseBuffer, accumulatedResponse, domain](boost::system::error_code ec, std::size_t bytesTransferred)
                                {
                                    if (!ec || ec == boost::asio::error::eof)
                                    {
                                        std::istream responseStream(responseBuffer.get());
                                        accumulatedResponse->append(std::istreambuf_iterator<char>(responseStream), std::istreambuf_iterator<char>());

                                        if (ec == boost::asio::error::eof)
                                        {
                                            processAndForwardResponse(clientSocket, *accumulatedResponse, domain);
                                        }
                                        else
                                        {
                                            readServerResponse(clientSocket, serverSocket, responseBuffer, accumulatedResponse, domain);
                                        }
                                    }
                                    else
                                    {
                                        std::cerr << "Error receiving response from server: " << ec.message() << " (Code: " << ec.value() << ")" << std::endl;
                                    }
                                });
    }

    // Function to process the accumulated response and forward it to the client
    void processAndForwardResponse(std::shared_ptr<tcp::socket> clientSocket, const std::string &responseContent, const std::string &domain)
    {
        auto headerEndPos = responseContent.find("\r\n\r\n");
        if (headerEndPos == std::string::npos)
        {
            std::cerr << "Malformed response: missing header-body separator." << std::endl;
            return;
        }

        std::string headers = responseContent.substr(0, headerEndPos + 4);
        std::string body = responseContent.substr(headerEndPos + 4);

        storeCookiesFromResponse(headers, getClientId(*clientSocket), domain);

        std::string fullResponse = headers + body;

        boost::asio::async_write(*clientSocket, boost::asio::buffer(fullResponse), [clientSocket](boost::system::error_code ec, std::size_t bytesSent)
                                 {
            if (!ec)
            {
                std::cout << "Response forwarded to client successfully." << std::endl;
            }
            else
            {
                std::cerr << "Error sending response to client: " << ec.message() << std::endl;
            } });
    }

    // Extract cookies from server response headers and store them for the client
    void storeCookiesFromResponse(const std::string &headers, const std::string &clientId, const std::string &domain)
    {
        std::regex setCookieRegex(R"(Set-Cookie:\s*([^=]+)=([^;]+);?)", std::regex::icase);
        std::sregex_iterator cookiesBegin(headers.begin(), headers.end(), setCookieRegex);
        std::sregex_iterator cookiesEnd;

        for (auto it = cookiesBegin; it != cookiesEnd; ++it)
        {
            std::string cookieName = it->str(1);
            std::string cookieValue = it->str(2);

            clientCookies[clientId][domain][cookieName] = cookieValue;
            std::cout << "Stored cookie for client " << clientId << " from domain " << domain << ": " << cookieName << "=" << cookieValue << std::endl;
        }
    }

    // Function to add cookies to the request before forwarding
    void addCookiesToRequest(std::string &request, const std::string &clientId, const std::string &domain)
    {
        if (clientCookies.find(clientId) != clientCookies.end() && clientCookies[clientId].find(domain) != clientCookies[clientId].end())
        {
            const auto &cookies = clientCookies[clientId][domain];
            std::string cookieHeader = "Cookie: ";
            bool cookiesPresent = false;
            for (const auto &[cookieName, cookieValue] : cookies)
            {
                cookieHeader += cookieName + "=" + cookieValue + "; ";
                cookiesPresent = true;
            }
            if (cookiesPresent)
            {
                // Track cookie patterns for analytics
                cookiePatterns[domain]++;

                request += cookieHeader + "\r\n";
                std::cout << "Added cookies to request: " << cookieHeader << std::endl;

                std::cout << "Cookie Access frequency for " << domain << ": " << cookiePatterns[domain] << std::endl;
            }
            else
            {
                std::cout << "No cookies found for client " << clientId << " and domain " << domain << std::endl;
            }
        }
        else
        {
            std::cout << "No cookies found for client " << clientId << " and domain " << domain << std::endl;
        }
    }

    // Main handleRequest function that coordinates the request parsing and forwarding
    void handleRequest(std::shared_ptr<tcp::socket> clientSocket)
    {
        auto requestBuffer = std::make_shared<boost::asio::streambuf>();

        boost::asio::async_read_until(*clientSocket, *requestBuffer, "\r\n\r\n", [this, clientSocket, requestBuffer](boost::system::error_code ec, std::size_t)
                                      {
            if (!ec)
            {
                std::istream requestStream(requestBuffer.get());
                std::string requestLine;
                std::getline(requestStream, requestLine);
                requestLine = trim(requestLine);

                std::cout << "Received request line: " << requestLine << std::endl;

                std::string host, path, version, port;
                if (parseRequest(requestLine, requestStream, host, path, version, port))
                {
                    std::cout << "Parsed host: " << host << ", path: " << path << ", version: " << version << ", port: " << port << std::endl;
                    forwardRequest(clientSocket, host, path, version, port);
                }
                else
                {
                    std::cerr << "Invalid request: Could not parse host." << std::endl;
                }
            }
            else
            {
                std::cerr << "Error reading request: " << ec.message() << std::endl;
            } });
    }

    tcp::acceptor acceptor_;
};

int main()
{
    try
    {
        boost::asio::io_context io_context;
        ProxyServer server(io_context, 8080);
        io_context.run();

        // For reporting analytics (could be moved to a separate thread or called periodically)
        server.printAnalytics();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}
