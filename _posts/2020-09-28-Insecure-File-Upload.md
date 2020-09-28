---
title: Insecure File Upload Vulnerability Explained
date: 2020-09-28 15:54:00 +0300
categories: [Web Security]
tags: [file-upload, web, vulnerability]     # TAG names should always be lowercase
---

# Insecure File Upload

Alright guys... It has been so long since the last time I've written a blog post. So I'd like to apologize for my mistakes in advance.

Finally being done with finals, I had some time to spend on HackTheBox the other day. I'm not going to name the machine to avoid ruining people's HTB adventures with spoilers, but I can say the user for the machine was web heavy. 

> Oh this box is gonna be a breeze.

At least that was my initial though since my strong side is web. In order to get a shell on the machine, I had to exploit two different web vulnerabilities. The first one, widely known SQL Injection was a breeze. The second one, however, was not as easy as I thought. It was no other than the infamous Insecure File Upload vulnerability. After reading a bunch of tutorials, reference sheets and articles, I want to share what I learned about the particular vulnerability type. 

**Disclaimer:** This article is not a HackTheBox machine walkthrough, instead we we'll be focusing on a vulnerability type that is still seen in wild and in CTFs.

Let's dive right in.

### Protections Against File Upload

Insecure File Upload vulnerability is basically abusing web application's file upload functionality to upload a malicious file to the system like a reverse shell. In order for this attack to be impactful, we need a file upload that we can upload malicious files and we should know the location those malicious files are stored. Once accomplished, they can lead to Remote Code Executions.

Let's look at the different ways developers try to protect against Insecure File Upload vulnerabilities.

### White-Listing File Extensions

White-listing is basically checking and making sure the uploaded file's extension is one of the allowed extension types. However, this approach is not flawless. There are a couple ways a white-list protection can be bypassed. 

Let's say our super-secure developer coded a file upload and used the following check as a white-list protection.

```php
<?php
    $file = $_FILES['file']['name'];
    $extension = explode(".", $file)[1];
    if ($extension == "jpeg" || $extension == "jpg" || $extension == "png") {
        echo "File Uploaded";
        // Do the necessary operations
    } else {
        echo "Only JPG/JPEG and PNG files are allowed";
    }
?>
```

**Note:** Most of the code in this article will be in PHP as it is still the most common language used in CTFs and in the real world. However, the methods described in this article applies to other languages as well.

This file gets the filename from the user, trust the filename (*big mistake),* splits the filename from the dots and tries to get the filename. A malicious attacker can easily bypass this check by sending a file called shell.jpg.php . The code would get the filename, split it into  ['shell', 'jpg', 'php'], check the element in the first index which is "jpg" and assume it is a safe image file. In reality, we just uploaded a php script that can give us a reverse shell in the target system.

**Is it always this easy?**

HELL NO! Although this is an example that can still be seen in wild, most web applications are more complex than that these days. Web languages and frameworks offer various methods/functions to fight against these types of vulnerabilities and developers are getting smarter everyday but so do the attackers. 

Let's talk about other ways to bypass the white-list protection. To keep the article brief, I'm not going to include code snippets for all of them but try to imagine the code in the back-end as we go through them.

Some developers try to check the last extension to prevent the bypass described above. Smarter ones utilize their programming language's or framework's *trusted* functions to check your input's credibility. Even those *trusted* functions might not be as trustworthy as they seem. Due to the ways some of them interpret the given string, it is possible to bypass them.

```
shell.php?shell.jpeg
shell.php%00shell.png
```

Have a look at the filenames above. In some cases, *super secure functions* validate these as valid filenames. However, when it comes to calling and using the filename, system's does not interpret them as those functions. If you are not familiar with C-like programming languages, null-byte (%00) indicates the end of a string. Therefore, some systems interpret that filename as shell.php, again letting us upload a shell. 

This might not always work but null-byte injection is more common than you might think. 

### Black-Listing File Extensions

As an opposite approach to white-listing, black-listing file extensions marks some extensions (like .php, .sh etc.) to prevent a malicious attacker from running code on the servers. If not done correctly, this approach is easier to bypass than white-listing protection.

If the check in place only checks if the extension is .php, one can easily bypass the check by capitalizing letters like .PhP, or using other valid PHP extensions. There are many extensions you can use to make PHP code work. 

Some of those extensions are:

- .php5
- .pht
- .phar

More of those can be found in:

[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20PHP)

### Content-Type Validations

Another primitive check employed by developers is checking the content-type sent by the request to make sure it is an expected file-type. What they fail to realize is that just like every other field in a HTTP request, content-type can be modified by the user. 

![Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_3.38.42_PM.png](Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_3.38.42_PM.png)

A normal request to upload php code to the site.

This request can be modified to look like the following picture to avoid some server-side protection against file upload.

![Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_3.40.07_PM.png](Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_3.40.07_PM.png)

If the developer only checks the type using the user supplied Content-Type header, it is awfully easy to bypass this check.

### Content-Length Validation

This is not a check I've run into in the wild or in the CTFs so I won't dive into this bypass deeply. Having said that some resource state that there are applications that checks the content length to try and understand if the image file uploaded has a length that is more than usual.

Some of these checks can be bypassed changing the Content-Length header or embedding as short commands as possible. Instead of embedding a full-blown reverse shell like in the above image, the attacker can just embed commands one by one to gain RCE.

In my experience, it might be useful to embed the code in advance instead of changing the contents of the file in Burp Intercept, especially in CTFs. In some cases, applications check if the length of the content you've uploaded corresponds to the length in Content-Length header. So if you change the contents of the file when intercepted, the application might be able to detect that unless you change the Content-Length header too. This is particularly a good tip for the last, but certainly not least type of bypass that will be mentioned in this article.

### Magic Bytes Validation

Let's get into more fun stuff. As hackers come up with creative ways to break security mechanism, developers keep coming up with smarter code. Early on, we talked about a very primitive way to bypass server-side file upload protection: changing Content-Type header. Obviously, developers had to come up with a better approach to check the file type. One approach proposed is checking the magic bytes of files. Every file includes a couple bytes called magic bytes as the first bytes to identify the filetype. This is not dependent on file extension. You cannot change the magic bytes by just changing the filetype. Security mechanisms tend to check these bytes to validate the type of file. However, these bytes can easily be manipulated by the user. 

```
GIF89a;
```

Sometimes adding the string seen above at the beginning of a file is enough to trick applications to interpret the file as a GIF file. 

Another method I prefer is embedding the malicious code directly into a PNG/JPEG file. This is as easy as copying the code and pasting it somewhere in the PNG file (except for the beginning). Once done, you can check the file type using the following command in UNIX based systems.

![Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_4.06.25_PM.png](Insecure%20File%20Upload%204bc365a31a534f1ca67e16fdced83c02/Screen_Shot_2020-05-25_at_4.06.25_PM.png)

In order to get RCE with this method, you have to find a way to send the file with the relevant file extension (.php in this case). If the system successfully prevents you from uploading files with that file extension, you can't run it once it is on the system. There are some examples, however, that let's user get a working shell by sending files with double extensions such as reverse-shell.php.jpeg.

### Future Work

Insecure File Uploads are not necessarily my strongest web vulnerability but I find the bypasses above interesting and the results can be devastating. While working on the HTB machine I mentioned before, I realized there is no de-facto tool to automatize insecure file upload tests. My next goal is writing a tool that can check such vulnerabilities automatically. This would be something like SQLMap but for file uploads. If you have ideas and want to help or if you already know a tool that can do this with high success rates, reach out to me.

### More To Read

In this section, I'll include some more links to read more about Insecure File Uploads and to practice exploiting them.

- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Vict0ni's 0x00sec Post (Vulnerability He Found in the Wild)](https://0x00sec.org/t/unrestricted-cv-file-upload/20325)