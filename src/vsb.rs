//! Varnish String Buffer (VSB) - Rust implementation
//!
//! This module provides a port of the Varnish String Buffer utility from C to Rust.
//! VSB is a dynamically growing string builder optimized for building strings
//! incrementally with automatic memory management.
//!
//! # Examples
//!
//! ```
//! use vsb::Vsb;
//!
//! let mut vsb = Vsb::new();
//! vsb.cat("Hello, ");
//! vsb.cat("world!");
//! assert_eq!(vsb.as_str(), "Hello, world!");
//! ```
//!
//! ```
//! use std::fmt::Write;
//! use vsb::Vsb;
//!
//! let mut vsb = Vsb::new();
//! write!(&mut vsb, "The answer is {}", 42).unwrap();
//! assert_eq!(vsb.as_str(), "The answer is 42");
//! ```

use std::fmt;
use std::io;

/// A dynamically growing string buffer.
///
/// `Vsb` provides an efficient way to build strings incrementally. It automatically
/// grows as needed and provides methods for appending strings, bytes, and formatted
/// output.
///
/// # C API Mapping
///
/// | C Function         | Rust Equivalent         |
/// |--------------------|-------------------------|
/// | `VSB_new_auto()`   | `Vsb::new()`           |
/// | `VSB_cat()`        | `cat()` / `push_str()` |
/// | `VSB_bcat()`       | `bcat()` / `extend()`  |
/// | `VSB_printf()`     | `write!()` macro       |
/// | `VSB_putc()`       | `push()` / `push_byte()` |
/// | `VSB_finish()`     | implicit (not required) |
/// | `VSB_data()`       | `as_str()` / `as_bytes()` |
/// | `VSB_len()`        | `len()`                |
/// | `VSB_clear()`      | `clear()`              |
/// | `VSB_destroy()`    | automatic (Drop)       |
#[derive(Debug, Clone)]
pub struct Vsb {
    /// The underlying buffer storing the string data
    buf: Vec<u8>,
    /// Current indentation level (number of spaces)
    indent: usize,
    /// Whether we're at the start of a line (for indentation)
    at_line_start: bool,
}

impl Vsb {
    /// Creates a new empty `Vsb`.
    ///
    /// This is equivalent to C's `VSB_new_auto()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let vsb = Vsb::new();
    /// assert_eq!(vsb.len(), 0);
    /// assert!(vsb.is_empty());
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            indent: 0,
            at_line_start: true,
        }
    }

    /// Creates a new `Vsb` with the specified capacity.
    ///
    /// The buffer will be able to hold at least `capacity` bytes without
    /// reallocating. If `capacity` is 0, the buffer will not allocate.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let vsb = Vsb::with_capacity(100);
    /// assert!(vsb.capacity() >= 100);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            indent: 0,
            at_line_start: true,
        }
    }

    /// Appends a string slice to the buffer.
    ///
    /// This is equivalent to C's `VSB_cat()`. Handles indentation automatically
    /// when newlines are encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.cat("Hello");
    /// vsb.cat(", world!");
    /// assert_eq!(vsb.as_str(), "Hello, world!");
    /// ```
    pub fn cat(&mut self, s: &str) {
        if self.indent == 0 {
            // Fast path: no indentation
            self.buf.extend_from_slice(s.as_bytes());
            self.at_line_start = s.ends_with('\n');
        } else {
            // Handle indentation for each line
            for line in s.split_inclusive('\n') {
                // Only indent if we're at line start and the line has content (not just \n)
                if self.at_line_start && self.indent > 0 && !line.is_empty() && line != "\n" {
                    // Insert indentation
                    self.buf.extend(std::iter::repeat_n(b' ', self.indent));
                }
                self.buf.extend_from_slice(line.as_bytes());
                self.at_line_start = line.ends_with('\n');
            }
        }
    }

    /// Appends a byte slice to the buffer.
    ///
    /// This is equivalent to C's `VSB_bcat()`. Does not handle indentation
    /// (unlike `cat()`), as the data may not be valid UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.bcat(&[72, 101, 108, 108, 111]); // "Hello"
    /// assert_eq!(vsb.as_bytes(), &[72, 101, 108, 108, 111]);
    /// ```
    #[inline]
    pub fn bcat(&mut self, bytes: &[u8]) {
        // For binary data, we don't apply indentation
        self.buf.extend_from_slice(bytes);
        // Track if we ended with a newline for future string operations
        if let Some(&last) = bytes.last() {
            self.at_line_start = last == b'\n';
        }
    }

    /// Appends a single byte to the buffer.
    ///
    /// This is equivalent to C's `VSB_putc()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.push_byte(b'A');
    /// vsb.push_byte(b'B');
    /// assert_eq!(vsb.as_bytes(), b"AB");
    /// ```
    #[inline]
    pub fn push_byte(&mut self, byte: u8) {
        if self.at_line_start && self.indent > 0 && byte != b'\n' {
            self.buf.extend(std::iter::repeat_n(b' ', self.indent));
        }
        self.buf.push(byte);
        self.at_line_start = byte == b'\n';
    }

    /// Appends a single character to the buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.push('A');
    /// vsb.push('B');
    /// assert_eq!(vsb.as_str(), "AB");
    /// ```
    pub fn push(&mut self, ch: char) {
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        self.cat(s);
    }

    /// Clears the buffer, removing all contents.
    ///
    /// This is equivalent to C's `VSB_clear()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.cat("Hello");
    /// assert_eq!(vsb.len(), 5);
    /// vsb.clear();
    /// assert_eq!(vsb.len(), 0);
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear();
        self.indent = 0;
        self.at_line_start = true;
    }

    /// Returns the contents of the buffer as a string slice.
    ///
    /// This is equivalent to C's `VSB_data()`, but does not require calling
    /// "finish" first. Returns an empty string if the buffer is not valid UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.cat("Hello, world!");
    /// assert_eq!(vsb.as_str(), "Hello, world!");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        // Safe because we only add valid UTF-8 through cat() and push()
        // bcat() can add invalid UTF-8, so we use from_utf8_lossy
        std::str::from_utf8(&self.buf).unwrap_or("")
    }

    /// Returns the contents of the buffer as a byte slice.
    ///
    /// This provides access to the raw bytes, useful when binary data has been
    /// added via `bcat()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.bcat(&[1, 2, 3, 4]);
    /// assert_eq!(vsb.as_bytes(), &[1, 2, 3, 4]);
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the length of the buffer in bytes.
    ///
    /// This is equivalent to C's `VSB_len()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.cat("Hello");
    /// assert_eq!(vsb.len(), 5);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// assert!(vsb.is_empty());
    /// vsb.cat("Hello");
    /// assert!(!vsb.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns the capacity of the buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let vsb = Vsb::with_capacity(100);
    /// assert!(vsb.capacity() >= 100);
    /// ```
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Reserves capacity for at least `additional` more bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.reserve(100);
    /// assert!(vsb.capacity() >= 100);
    /// ```
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    /// Increases the indentation level by the specified amount.
    ///
    /// Indentation is applied at the start of each new line when using `cat()` or `push()`.
    ///
    /// This is equivalent to C's `VSB_indent()` with a positive value.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.indent(4);
    /// vsb.cat("Hello\nWorld");
    /// assert_eq!(vsb.as_str(), "    Hello\n    World");
    /// ```
    #[inline]
    pub fn indent(&mut self, spaces: usize) {
        self.indent = self.indent.saturating_add(spaces);
    }

    /// Decreases the indentation level by the specified amount.
    ///
    /// This is equivalent to C's `VSB_indent()` with a negative value.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.indent(8);
    /// vsb.cat("Hello\n");
    /// vsb.dedent(4);
    /// vsb.cat("World");
    /// assert_eq!(vsb.as_str(), "    Hello\n    World");
    /// ```
    #[inline]
    pub fn dedent(&mut self, spaces: usize) {
        self.indent = self.indent.saturating_sub(spaces);
    }

    /// Sets the indentation level to the specified value.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.set_indent(4);
    /// vsb.cat("Hello");
    /// assert_eq!(vsb.as_str(), "    Hello");
    /// ```
    #[inline]
    pub fn set_indent(&mut self, spaces: usize) {
        self.indent = spaces;
    }

    /// Returns the current indentation level.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// assert_eq!(vsb.get_indent(), 0);
    /// vsb.indent(4);
    /// assert_eq!(vsb.get_indent(), 4);
    /// ```
    #[inline]
    pub fn get_indent(&self) -> usize {
        self.indent
    }

    /// Consumes the `Vsb` and returns the underlying `String`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer contains invalid UTF-8. Use `into_bytes()` if
    /// the buffer might contain binary data.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.cat("Hello");
    /// let s = vsb.into_string();
    /// assert_eq!(s, "Hello");
    /// ```
    pub fn into_string(self) -> String {
        String::from_utf8(self.buf).expect("VSB contains invalid UTF-8")
    }

    /// Consumes the `Vsb` and returns the underlying byte vector.
    ///
    /// # Examples
    ///
    /// ```
    /// use vsb::Vsb;
    ///
    /// let mut vsb = Vsb::new();
    /// vsb.bcat(&[1, 2, 3]);
    /// let bytes = vsb.into_bytes();
    /// assert_eq!(bytes, vec![1, 2, 3]);
    /// ```
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for Vsb {
    fn default() -> Self {
        Self::new()
    }
}

/// Implement `std::fmt::Write` to support format! macros.
///
/// This enables using `write!()` and `writeln!()` macros with `Vsb`,
/// providing equivalent functionality to C's `VSB_printf()`.
///
/// # Examples
///
/// ```
/// use std::fmt::Write;
/// use vsb::Vsb;
///
/// let mut vsb = Vsb::new();
/// write!(&mut vsb, "Hello, {}!", "world").unwrap();
/// assert_eq!(vsb.as_str(), "Hello, world!");
/// ```
impl fmt::Write for Vsb {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.cat(s);
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.push(c);
        Ok(())
    }
}

/// Implement `std::io::Write` for completeness.
///
/// This allows `Vsb` to be used anywhere an `io::Write` is expected.
///
/// # Examples
///
/// ```
/// use std::io::Write;
/// use vsb::Vsb;
///
/// let mut vsb = Vsb::new();
/// vsb.write_all(b"Hello").unwrap();
/// assert_eq!(vsb.as_bytes(), b"Hello");
/// ```
impl io::Write for Vsb {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bcat(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Additional trait implementations for convenience

impl AsRef<str> for Vsb {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Vsb {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<String> for Vsb {
    fn from(s: String) -> Self {
        Self {
            buf: s.into_bytes(),
            indent: 0,
            at_line_start: false,
        }
    }
}

impl From<&str> for Vsb {
    fn from(s: &str) -> Self {
        let mut vsb = Self::new();
        vsb.cat(s);
        vsb
    }
}

impl From<Vec<u8>> for Vsb {
    fn from(buf: Vec<u8>) -> Self {
        let at_line_start = buf.last().is_none_or(|&b| b == b'\n');
        Self {
            buf,
            indent: 0,
            at_line_start,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as FmtWrite;
    use std::io::Write as IoWrite;

    #[test]
    fn test_new() {
        let vsb = Vsb::new();
        assert_eq!(vsb.len(), 0);
        assert!(vsb.is_empty());
        assert_eq!(vsb.as_str(), "");
    }

    #[test]
    fn test_with_capacity() {
        let vsb = Vsb::with_capacity(100);
        assert!(vsb.capacity() >= 100);
        assert_eq!(vsb.len(), 0);
    }

    #[test]
    fn test_cat() {
        let mut vsb = Vsb::new();
        vsb.cat("Hello");
        assert_eq!(vsb.as_str(), "Hello");
        vsb.cat(", world!");
        assert_eq!(vsb.as_str(), "Hello, world!");
    }

    #[test]
    fn test_bcat() {
        let mut vsb = Vsb::new();
        vsb.bcat(b"Hello");
        assert_eq!(vsb.as_bytes(), b"Hello");
        vsb.bcat(b", world!");
        assert_eq!(vsb.as_bytes(), b"Hello, world!");
    }

    #[test]
    fn test_push_byte() {
        let mut vsb = Vsb::new();
        vsb.push_byte(b'A');
        vsb.push_byte(b'B');
        vsb.push_byte(b'C');
        assert_eq!(vsb.as_str(), "ABC");
    }

    #[test]
    fn test_push() {
        let mut vsb = Vsb::new();
        vsb.push('H');
        vsb.push('i');
        vsb.push('!');
        assert_eq!(vsb.as_str(), "Hi!");
    }

    #[test]
    fn test_push_unicode() {
        let mut vsb = Vsb::new();
        vsb.push('🦀');
        vsb.push('🚀');
        assert_eq!(vsb.as_str(), "🦀🚀");
    }

    #[test]
    fn test_clear() {
        let mut vsb = Vsb::new();
        vsb.cat("Hello");
        assert_eq!(vsb.len(), 5);
        vsb.clear();
        assert_eq!(vsb.len(), 0);
        assert!(vsb.is_empty());
        assert_eq!(vsb.as_str(), "");
    }

    #[test]
    fn test_len() {
        let mut vsb = Vsb::new();
        assert_eq!(vsb.len(), 0);
        vsb.cat("Hello");
        assert_eq!(vsb.len(), 5);
        vsb.cat(" world");
        assert_eq!(vsb.len(), 11);
    }

    #[test]
    fn test_is_empty() {
        let mut vsb = Vsb::new();
        assert!(vsb.is_empty());
        vsb.cat("a");
        assert!(!vsb.is_empty());
        vsb.clear();
        assert!(vsb.is_empty());
    }

    #[test]
    fn test_reserve() {
        let mut vsb = Vsb::new();
        vsb.reserve(1000);
        assert!(vsb.capacity() >= 1000);
    }

    #[test]
    fn test_fmt_write() {
        let mut vsb = Vsb::new();
        FmtWrite::write_fmt(&mut vsb, format_args!("The answer is {}", 42)).unwrap();
        assert_eq!(vsb.as_str(), "The answer is 42");
    }

    #[test]
    fn test_fmt_write_complex() {
        let mut vsb = Vsb::new();
        FmtWrite::write_fmt(&mut vsb, format_args!("{} + {} = {}", 1, 2, 3)).unwrap();
        FmtWrite::write_str(&mut vsb, "!\n").unwrap();
        FmtWrite::write_str(&mut vsb, "Done").unwrap();
        assert_eq!(vsb.as_str(), "1 + 2 = 3!\nDone");
    }

    #[test]
    fn test_io_write() {
        let mut vsb = Vsb::new();
        vsb.write_all(b"Hello").unwrap();
        vsb.write_all(b", world!").unwrap();
        assert_eq!(vsb.as_bytes(), b"Hello, world!");
    }

    #[test]
    fn test_indent_basic() {
        let mut vsb = Vsb::new();
        vsb.indent(4);
        vsb.cat("Hello");
        assert_eq!(vsb.as_str(), "    Hello");
    }

    #[test]
    fn test_indent_multiline() {
        let mut vsb = Vsb::new();
        vsb.indent(4);
        vsb.cat("Hello\nWorld");
        assert_eq!(vsb.as_str(), "    Hello\n    World");
    }

    #[test]
    fn test_indent_nested() {
        let mut vsb = Vsb::new();
        vsb.indent(2);
        vsb.cat("Level 1\n");
        vsb.indent(2);
        vsb.cat("Level 2\n");
        vsb.dedent(2);
        vsb.cat("Back to Level 1");
        assert_eq!(vsb.as_str(), "  Level 1\n    Level 2\n  Back to Level 1");
    }

    #[test]
    fn test_dedent() {
        let mut vsb = Vsb::new();
        vsb.indent(8);
        vsb.cat("Hello\n");
        vsb.dedent(4);
        vsb.cat("World");
        assert_eq!(vsb.as_str(), "        Hello\n    World");
    }

    #[test]
    fn test_dedent_underflow() {
        let mut vsb = Vsb::new();
        vsb.indent(2);
        vsb.dedent(10); // Should saturate at 0
        vsb.cat("Hello");
        assert_eq!(vsb.as_str(), "Hello");
    }

    #[test]
    fn test_set_indent() {
        let mut vsb = Vsb::new();
        vsb.set_indent(6);
        vsb.cat("Hello");
        assert_eq!(vsb.as_str(), "      Hello");
    }

    #[test]
    fn test_get_indent() {
        let mut vsb = Vsb::new();
        assert_eq!(vsb.get_indent(), 0);
        vsb.indent(4);
        assert_eq!(vsb.get_indent(), 4);
        vsb.indent(2);
        assert_eq!(vsb.get_indent(), 6);
        vsb.dedent(3);
        assert_eq!(vsb.get_indent(), 3);
    }

    #[test]
    fn test_indent_empty_lines() {
        let mut vsb = Vsb::new();
        vsb.indent(4);
        vsb.cat("Hello\n\nWorld");
        // Empty line should still get indentation
        assert_eq!(vsb.as_str(), "    Hello\n\n    World");
    }

    #[test]
    fn test_into_string() {
        let mut vsb = Vsb::new();
        vsb.cat("Hello, world!");
        let s = vsb.into_string();
        assert_eq!(s, "Hello, world!");
    }

    #[test]
    fn test_into_bytes() {
        let mut vsb = Vsb::new();
        vsb.bcat(&[1, 2, 3, 4, 5]);
        let bytes = vsb.into_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_from_string() {
        let s = String::from("Hello");
        let vsb = Vsb::from(s);
        assert_eq!(vsb.as_str(), "Hello");
    }

    #[test]
    fn test_from_str() {
        let vsb = Vsb::from("Hello, world!");
        assert_eq!(vsb.as_str(), "Hello, world!");
    }

    #[test]
    fn test_from_vec() {
        let vec = vec![72, 101, 108, 108, 111]; // "Hello"
        let vsb = Vsb::from(vec);
        assert_eq!(vsb.as_bytes(), b"Hello");
    }

    #[test]
    fn test_as_ref_str() {
        let mut vsb = Vsb::new();
        vsb.cat("Hello");
        let s: &str = vsb.as_ref();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_as_ref_bytes() {
        let mut vsb = Vsb::new();
        vsb.bcat(&[1, 2, 3]);
        let bytes: &[u8] = vsb.as_ref();
        assert_eq!(bytes, &[1, 2, 3]);
    }

    #[test]
    fn test_clone() {
        let mut vsb1 = Vsb::new();
        vsb1.cat("Hello");
        let mut vsb2 = vsb1.clone();
        vsb2.cat(", world!");
        assert_eq!(vsb1.as_str(), "Hello");
        assert_eq!(vsb2.as_str(), "Hello, world!");
    }

    #[test]
    fn test_default() {
        let vsb = Vsb::default();
        assert_eq!(vsb.len(), 0);
        assert!(vsb.is_empty());
    }

    #[test]
    fn test_large_string() {
        let mut vsb = Vsb::new();
        let large_str = "x".repeat(10000);
        vsb.cat(&large_str);
        assert_eq!(vsb.len(), 10000);
        assert_eq!(vsb.as_str(), large_str);
    }

    #[test]
    fn test_many_small_appends() {
        let mut vsb = Vsb::new();
        for i in 0..1000 {
            FmtWrite::write_fmt(&mut vsb, format_args!("{},", i)).unwrap();
        }
        assert!(vsb.as_str().starts_with("0,1,2,3,4,"));
        assert!(vsb.as_str().ends_with(",999,"));
    }

    #[test]
    fn test_mixed_operations() {
        let mut vsb = Vsb::new();
        vsb.cat("Line 1\n");
        vsb.bcat(b"Line 2\n");
        FmtWrite::write_fmt(&mut vsb, format_args!("Line {}\n", 3)).unwrap();
        vsb.push('4');
        assert_eq!(vsb.as_str(), "Line 1\nLine 2\nLine 3\n4");
    }

    #[test]
    fn test_binary_data() {
        let mut vsb = Vsb::new();
        vsb.bcat(&[0, 1, 2, 255, 254]);
        assert_eq!(vsb.as_bytes(), &[0, 1, 2, 255, 254]);
        // Binary data may not be valid UTF-8
        assert_eq!(vsb.len(), 5);
    }

    #[test]
    fn test_indent_with_format() {
        let mut vsb = Vsb::new();
        vsb.indent(2);
        FmtWrite::write_str(&mut vsb, "fn main() {\n").unwrap();
        vsb.indent(2);
        FmtWrite::write_str(&mut vsb, "println!(\"Hello\");\n").unwrap();
        vsb.dedent(2);
        FmtWrite::write_str(&mut vsb, "}").unwrap();
        assert_eq!(
            vsb.as_str(),
            "  fn main() {\n    println!(\"Hello\");\n  }"
        );
    }

    #[test]
    fn test_clear_resets_indent() {
        let mut vsb = Vsb::new();
        vsb.indent(4);
        vsb.cat("Hello");
        vsb.clear();
        assert_eq!(vsb.get_indent(), 0);
        vsb.cat("World");
        assert_eq!(vsb.as_str(), "World");
    }

    #[test]
    fn test_empty_cat() {
        let mut vsb = Vsb::new();
        vsb.cat("");
        assert_eq!(vsb.as_str(), "");
        vsb.cat("Hello");
        vsb.cat("");
        assert_eq!(vsb.as_str(), "Hello");
    }

    #[test]
    fn test_empty_bcat() {
        let mut vsb = Vsb::new();
        vsb.bcat(&[]);
        assert_eq!(vsb.len(), 0);
    }
}
