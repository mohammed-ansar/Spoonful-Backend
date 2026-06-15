const createSlugBase = (value = "") => {
  const slug = String(value)
    .toLowerCase()
    .replace(/\([^)]*\)/g, " ")
    .replace(/[^a-z0-9\s-]/g, " ")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  return slug || "product";
};

module.exports = { createSlugBase };
