#pragma once

#include <Unknwn.h>
#include <string>
#include <span>
#include <wil/resource.h>
#include <wil/com.h>
#include <winrt/base.h>
#include <ncryptprotect.h>

struct DataProtectionBuffer
{
    DataProtectionBuffer() = default;
    DataProtectionBuffer(DataProtectionBuffer const&) = delete;
    DataProtectionBuffer& operator=(DataProtectionBuffer const&) = delete;

    DataProtectionBuffer(wil::unique_hlocal_ptr<> data, uint32_t size) : m_data(std::move(data)), m_size(size)
    {
    }

    DataProtectionBuffer(DataProtectionBuffer&&) = default;
    DataProtectionBuffer& operator=(DataProtectionBuffer&&) = default;

    ~DataProtectionBuffer() = default;

    template<typename T> auto as_span() const
    {
        return std::span<T const>{reinterpret_cast<T const*>(m_data.get()), m_size / sizeof(T) };
    }

    void const* data() const { return m_data.get(); }
    uint32_t size() const { return m_size; }

private:
    wil::unique_hlocal_ptr<> m_data{};
    uint32_t m_size{};
};

struct DataProtectionStreamWriter : winrt::implements<DataProtectionStreamWriter, ::IStream, ::ISequentialStream>
{
    void encrypt_to_stream(NCRYPT_DESCRIPTOR_HANDLE descriptor, IStream* lower);
    void decrypt_to_stream(IStream* lower);
    void finish();

protected:
    STDMETHODIMP Write(void const* pv, ULONG size, ULONG* pcbWritten) noexcept override;
    STDMETHODIMP Commit(ULONG) noexcept override;
    STDMETHODIMP Read(void*, ULONG, ULONG* read) noexcept override;
    STDMETHODIMP Revert() noexcept override;
    STDMETHODIMP Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER* newPos) noexcept override;
    STDMETHODIMP SetSize(ULARGE_INTEGER) noexcept override;
    STDMETHODIMP CopyTo(::IStream*, ULARGE_INTEGER, ULARGE_INTEGER* read, ULARGE_INTEGER* written) noexcept override;
    STDMETHODIMP Clone(IStream** result) noexcept override;
    STDMETHODIMP Stat(STATSTG* stats, DWORD) noexcept override;
    STDMETHODIMP LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;
    STDMETHODIMP UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept override;

private:
    wil::com_ptr<::IStream> m_lower{ nullptr };
    NCRYPT_STREAM_HANDLE m_handle{ nullptr };
    NCRYPT_PROTECT_STREAM_INFO m_streamInfo{};
};

struct DataProtectionProvider
{
    DataProtectionProvider(std::wstring const& scope = L"LOCAL=user");

    DataProtectionBuffer ProtectBuffer(std::span<uint8_t const> data);

    DataProtectionBuffer UnprotectBuffer(std::span<uint8_t const> data);

    // Creates an encryption filter stream. Writing cleartext data into the writer
    // pushes encrypted data into the 'output' stream on the other side. Be sure
    // to call "writer->Commit()" to complete the encryption operation. The returned
    // stream object is-an IStream & ISequentialStream, suitable for passing to other
    // methods that write to it. Note that it is write-only; any attempt to read from
    // the stream or seek it will fail.
    winrt::com_ptr<DataProtectionStreamWriter> CreateEncryptionStreamWriter(::IStream* outputStream);

    winrt::com_ptr<DataProtectionStreamWriter> CreateDecryptionStreamWriter(::IStream* outputStream);

    ~DataProtectionProvider();

private:
    NCRYPT_DESCRIPTOR_HANDLE m_descriptor = nullptr;
};